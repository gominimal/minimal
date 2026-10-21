//! Abstractions over reading data from the network.

use bytes::{Bytes, BytesMut};
use futures::future::FutureExt;
use google_cloud_storage::Error as GcsError;
use google_cloud_storage::client::Storage;
use reqwest::{Client, Error as ReqwestError, Request, Response, Url as UpstreamReqwestUrl};

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;

use crate::mirror::CacheOrigin;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;

/// Newtype of [reqwest::Url] to wire reqwest as a [FetchBackend].
#[derive(Clone, Debug)]
pub struct ReqwestUrl(UpstreamReqwestUrl);

impl TryFrom<String> for ReqwestUrl {
    type Error = url::ParseError;

    fn try_from(s: String) -> Result<Self, url::ParseError> {
        UpstreamReqwestUrl::parse(&s).map(ReqwestUrl)
    }
}

impl TryFrom<&str> for ReqwestUrl {
    type Error = url::ParseError;

    fn try_from(s: &str) -> Result<Self, url::ParseError> {
        UpstreamReqwestUrl::parse(s).map(ReqwestUrl)
    }
}

impl core::str::FromStr for ReqwestUrl {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, url::ParseError> {
        UpstreamReqwestUrl::parse(s).map(ReqwestUrl)
    }
}

impl From<UpstreamReqwestUrl> for ReqwestUrl {
    fn from(url: UpstreamReqwestUrl) -> Self {
        Self(url)
    }
}

impl ReqwestUrl {
    /// The host the URL names, without its scheme or port: the host a fetch
    /// of this URL leaves for, read from the parsed URL rather than from a
    /// rendering of it.
    pub fn host_str(&self) -> Option<&str> {
        self.0.host_str()
    }

    /// The port the URL names, when it has one: the other half of the host
    /// a fetch record spells from, read from the parsed URL the same way
    /// [`host_str`]'s half is, never from a rendering of it. Whether the
    /// record carries that port is the record's own one port rule's to
    /// say, so this hands back the URL's own fact and nothing more.
    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }
}

/// The response to an RPC for some resource.
pub trait FetchResponse: std::fmt::Debug + Sized {
    type Error: std::fmt::Debug;

    fn error_for_status(self) -> Result<Self, Self::Error>;
    fn is_success(&self) -> bool;
    fn status_code(&self) -> usize;
    fn content_length(&self) -> Option<u64>;

    fn bytes(self) -> impl Future<Output = Result<Bytes, Self::Error>> + Send;

    fn chunk(&mut self) -> impl Future<Output = Result<Option<Bytes>, Self::Error>>;

    /// Returns the underlying object's GCS generation, if the backend exposes
    /// one. Backends without versioned-object semantics (e.g. plain HTTPS)
    /// return `None` via the default impl. Used by writers to do
    /// compare-and-swap on subsequent writes.
    fn generation(&self) -> Option<i64> {
        None
    }
}

impl FetchResponse for Response {
    type Error = ReqwestError;

    fn is_success(&self) -> bool {
        self.status().is_success()
    }
    fn status_code(&self) -> usize {
        self.status().as_u16() as usize
    }
    fn error_for_status(self) -> Result<Self, Self::Error> {
        Response::error_for_status(self)
    }
    fn content_length(&self) -> Option<u64> {
        self.content_length()
    }

    fn bytes(self) -> impl Future<Output = Result<Bytes, Self::Error>> {
        Response::bytes(self)
    }

    fn chunk(&mut self) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> {
        Response::chunk(self)
    }
}

/// A URL which can be consumed by implementations of [FetchBackend].
pub trait FetchUrl: std::fmt::Debug + Clone {
    type JoinError: std::fmt::Debug;
    fn join(&self, input: &str) -> Result<Self, Self::JoinError>;

    fn filename(&self) -> String;
}

impl FetchUrl for ReqwestUrl {
    type JoinError = url::ParseError;

    fn join(&self, input: &str) -> Result<Self, Self::JoinError> {
        UpstreamReqwestUrl::join(&self.0, input).map(ReqwestUrl)
    }
    fn filename(&self) -> String {
        let path = self.0.path();
        match path.rfind("/") {
            Some(idx) => path[idx + 1..].to_string(),
            None => path.to_string(),
        }
    }
}

/// An implementation that is able to make async network requests.
pub trait FetchBackend: std::fmt::Debug {
    type Url: FetchUrl;

    type Request: std::fmt::Debug;
    type Response: FetchResponse;

    fn get(
        &self,
        url: Self::Url,
    ) -> Result<Self::Request, <Self::Response as FetchResponse>::Error>;

    fn execute(
        &self,
        req: Self::Request,
    ) -> impl Future<Output = Result<Self::Response, <Self::Response as FetchResponse>::Error>>;
}

/// Wiring to allow reqwest to be used as a [FetchBackend].
impl FetchBackend for Client {
    type Url = ReqwestUrl;

    type Request = Request;
    type Response = Response;

    fn get(
        &self,
        url: Self::Url,
    ) -> Result<Self::Request, <Self::Response as FetchResponse>::Error> {
        self.get(url.0).build()
    }

    fn execute(
        &self,
        req: Self::Request,
    ) -> impl Future<Output = Result<Self::Response, <Self::Response as FetchResponse>::Error>>
    {
        self.execute(req)
    }
}

/// Newtype to wire GCS buckets as a [FetchUrl].
#[derive(Clone, Debug)]
pub struct GcsUrl {
    pub bucket: String,
    pub object: String,
}

impl FetchUrl for GcsUrl {
    type JoinError = ();

    fn join(&self, input: &str) -> Result<Self, Self::JoinError> {
        let mut out = self.clone();
        if out.object.is_empty() {
            out.object = input.into();
            Ok(out)
        } else {
            out.object.push('/');
            out.object.push_str(input);
            Ok(out)
        }
    }
    fn filename(&self) -> String {
        let url = &self.object;
        match url.rfind("/") {
            Some(idx) => url[idx + 1..].to_string(),
            None => url.to_string(),
        }
    }
}

impl FetchResponse for Result<google_cloud_storage::read_object::ReadObjectResponse, GcsError> {
    type Error = GcsError;

    fn is_success(&self) -> bool {
        self.is_ok()
    }
    fn error_for_status(self) -> Result<Self, Self::Error> {
        match self {
            Ok(_) => Ok(self),
            Err(e) => Err(e),
        }
    }

    async fn bytes(self) -> Result<Bytes, Self::Error> {
        let mut s = self?;
        let mut buf = BytesMut::with_capacity(s.object().size as usize);

        while let Some(chunk) = s.next().await {
            buf.extend_from_slice(&chunk?[..]);
        }

        Ok(buf.into())
    }

    fn chunk(&mut self) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> {
        let s = self.as_mut().unwrap();
        s.next().map(|v| match v {
            None => Ok(None),
            Some(Ok(chunk)) => Ok(Some(chunk)),
            Some(Err(e)) => Err(e),
        })
    }

    fn status_code(&self) -> usize {
        match self {
            Ok(_) => 200,
            Err(e) => {
                if let Some(sc) = e.http_status_code() {
                    sc as usize
                } else {
                    panic!("non-status error: {:?}", e);
                }
            }
        }
    }
    fn content_length(&self) -> Option<u64> {
        match self {
            Ok(s) => Some(s.object().size as u64),
            Err(_) => None,
        }
    }
    fn generation(&self) -> Option<i64> {
        match self {
            Ok(s) => Some(s.object().generation),
            Err(_) => None,
        }
    }
}

/// Wiring to allow GCS buckets to be used as a [FetchBackend].
impl FetchBackend for Storage {
    type Url = GcsUrl;

    type Request = google_cloud_storage::builder::storage::ReadObject;
    type Response = Result<google_cloud_storage::read_object::ReadObjectResponse, GcsError>;

    fn get(
        &self,
        url: Self::Url,
    ) -> Result<Self::Request, <Self::Response as FetchResponse>::Error> {
        Ok(self.read_object(url.bucket, url.object))
    }

    fn execute(
        &self,
        req: Self::Request,
    ) -> impl futures::Future<Output = Result<Self::Response, <Self::Response as FetchResponse>::Error>>
    {
        req.send().map(Ok)
    }
}

// --- Runtime-selectable backend --------------------------------------------
//
// The remote-cache *reader* needs to target either the GCS bucket (default) or
// a plain-HTTPS mirror (e.g. a Cloudflare R2 custom domain, to avoid GCS egress
// cost) chosen at runtime from config. Rather than thread a backend type
// parameter through every consumer of `RemoteCache`, `AnyBackend` selects the
// backend at construction and forwards each call to the chosen one. Writers
// keep using the concrete `Storage` backend (compare-and-swap needs GCS
// object generations, which plain HTTPS doesn't expose).

// ── The mirror transport ──────────────────────────────────────────────────────
//
// The mirror (spec MIR) answers HTTP/1.1 on a Unix socket on the host and on a
// vsock door in a guest. Neither is a URL a reqwest client can dial, so the
// mirror has a backend of its own: one hyper connection per request over the
// stream the endpoint names, with the same `FetchBackend` surface the HTTPS
// and GCS backends have, so the cache reader needs no second code path.

/// Where a mirror listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorEndpoint {
    /// A Unix socket on this machine: the host socket.
    Unix(PathBuf),
    /// A vsock door, dialled from inside a VM: the host's context id and the
    /// door's port.
    #[cfg(target_os = "linux")]
    Vsock { cid: u32, port: u32 },
}

impl fmt::Display for MirrorEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirrorEndpoint::Unix(path) => write!(f, "{}", path.display()),
            #[cfg(target_os = "linux")]
            MirrorEndpoint::Vsock { cid, port } => write!(f, "vsock:{cid}:{port}"),
        }
    }
}

/// A [FetchUrl] under a mirror: the endpoint and an absolute request path.
/// Joining a key under a cache mount works as [`url::Url::join`] does under an
/// `https` base, so the reader's keys land at `/-/c/<origin>/-/<key>`.
#[derive(Clone, Debug)]
pub struct MirrorUrl {
    pub endpoint: MirrorEndpoint,
    pub path: String,
}

impl MirrorUrl {
    /// A URL at an absolute request path.
    pub fn new(endpoint: MirrorEndpoint, path: impl Into<String>) -> Self {
        Self {
            endpoint,
            path: path.into(),
        }
    }

    /// The mount under which the mirror serves `origin`'s keys, the base a
    /// cache reader joins keys under.
    pub fn cache_mount(endpoint: MirrorEndpoint, origin: &CacheOrigin) -> Self {
        Self::new(endpoint, origin.mount())
    }
}

impl FetchUrl for MirrorUrl {
    type JoinError = Infallible;

    fn join(&self, input: &str) -> Result<Self, Self::JoinError> {
        let path = if input.starts_with('/') {
            input.to_string()
        } else {
            let dir_end = self.path.rfind('/').map(|i| i + 1).unwrap_or(0);
            format!("{}{input}", &self.path[..dir_end])
        };
        Ok(Self {
            endpoint: self.endpoint.clone(),
            path,
        })
    }

    fn filename(&self) -> String {
        match self.path.rfind('/') {
            Some(idx) => self.path[idx + 1..].to_string(),
            None => self.path.clone(),
        }
    }
}

/// What a fetch through the mirror can fail with.
#[derive(Debug)]
pub enum MirrorError {
    /// The endpoint did not accept a connection: the mirror is not running,
    /// or the door is not mapped.
    Connect {
        endpoint: MirrorEndpoint,
        source: std::io::Error,
    },
    /// The HTTP exchange broke after the connection opened.
    Transport(hyper::Error),
    /// The request could not be built.
    Request(http::Error),
    /// The mirror answered a status outside 2xx; `body` is what it said, so a
    /// 502 names the origin it could not reach (MIR-002).
    Status { status: u16, body: String },
}

impl fmt::Display for MirrorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirrorError::Connect { endpoint, source } => {
                write!(f, "the mirror at {endpoint} did not answer: {source}")
            }
            MirrorError::Transport(e) => write!(f, "the mirror connection failed: {e}"),
            MirrorError::Request(e) => write!(f, "the mirror request could not be built: {e}"),
            MirrorError::Status { status, body } if body.is_empty() => {
                write!(f, "the mirror answered {status}")
            }
            MirrorError::Status { body, .. } => f.write_str(body),
        }
    }
}

impl std::error::Error for MirrorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MirrorError::Connect { source, .. } => Some(source),
            MirrorError::Transport(e) => Some(e),
            MirrorError::Request(e) => Some(e),
            MirrorError::Status { .. } => None,
        }
    }
}

/// A request to the mirror: its URL and method.
#[derive(Debug)]
pub struct MirrorRequest {
    url: MirrorUrl,
    method: hyper::Method,
}

impl MirrorRequest {
    /// A `HEAD` request: the mirror fetches an unheld object as for a `GET`
    /// and answers with the headers alone (MIR-002).
    pub fn head(url: MirrorUrl) -> Self {
        Self {
            url,
            method: hyper::Method::HEAD,
        }
    }
}

/// How many bytes of a non-2xx body the client keeps for the error.
const ERROR_BODY_LIMIT: usize = 4096;

/// A response from the mirror.
#[derive(Debug)]
pub struct MirrorResponse {
    status: u16,
    content_length: Option<u64>,
    age: Option<u64>,
    body: Option<Incoming>,
    error_body: String,
}

impl MirrorResponse {
    /// The `Age` header, which the mirror sets on a copy it served because it
    /// could not reach the origin (MIR-004).
    pub fn age(&self) -> Option<u64> {
        self.age
    }
}

impl FetchResponse for MirrorResponse {
    type Error = MirrorError;

    fn error_for_status(self) -> Result<Self, Self::Error> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(MirrorError::Status {
                status: self.status,
                body: self.error_body,
            })
        }
    }
    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    fn status_code(&self) -> usize {
        self.status as usize
    }
    fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    async fn bytes(mut self) -> Result<Bytes, Self::Error> {
        let Some(body) = self.body.take() else {
            return Ok(Bytes::new());
        };
        body.collect()
            .await
            .map(|collected| collected.to_bytes())
            .map_err(MirrorError::Transport)
    }

    async fn chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
        let Some(body) = self.body.as_mut() else {
            return Ok(None);
        };
        loop {
            match body.frame().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(MirrorError::Transport(e)),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Ok(Some(data));
                    }
                    // A trailer frame carries no data; read on.
                }
            }
        }
    }
}

/// The mirror's [FetchBackend]: one HTTP/1.1 connection per request over the
/// endpoint's stream. Requests are local and few per object, so no pool.
#[derive(Clone, Debug, Default)]
pub struct MirrorClient {
    _private: (),
}

impl MirrorClient {
    pub fn new() -> Self {
        Self::default()
    }
}

type MirrorSender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

async fn open_mirror_connection(endpoint: &MirrorEndpoint) -> Result<MirrorSender, MirrorError> {
    let connect_err = |source| MirrorError::Connect {
        endpoint: endpoint.clone(),
        source,
    };
    match endpoint {
        MirrorEndpoint::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .map_err(connect_err)?;
            let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(MirrorError::Transport)?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::debug!(error = %e, "mirror connection ended with an error");
                }
            });
            Ok(sender)
        }
        #[cfg(target_os = "linux")]
        MirrorEndpoint::Vsock { cid, port } => {
            let stream =
                tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(*cid, *port))
                    .await
                    .map_err(connect_err)?;
            let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(MirrorError::Transport)?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::debug!(error = %e, "mirror door connection ended with an error");
                }
            });
            Ok(sender)
        }
    }
}

fn header_u64(headers: &http::HeaderMap, name: http::header::HeaderName) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

impl FetchBackend for MirrorClient {
    type Url = MirrorUrl;
    type Request = MirrorRequest;
    type Response = MirrorResponse;

    fn get(
        &self,
        url: Self::Url,
    ) -> Result<Self::Request, <Self::Response as FetchResponse>::Error> {
        Ok(MirrorRequest {
            url,
            method: hyper::Method::GET,
        })
    }

    async fn execute(
        &self,
        req: Self::Request,
    ) -> Result<Self::Response, <Self::Response as FetchResponse>::Error> {
        let mut sender = open_mirror_connection(&req.url.endpoint).await?;
        let request = http::Request::builder()
            .method(req.method)
            .uri(req.url.path.as_str())
            .header(http::header::HOST, "mirror")
            .body(Empty::<Bytes>::new())
            .map_err(MirrorError::Request)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(MirrorError::Transport)?;
        let status = response.status().as_u16();
        let content_length = header_u64(response.headers(), http::header::CONTENT_LENGTH);
        let age = header_u64(response.headers(), http::header::AGE);
        let mut body = response.into_body();
        let mut error_body = String::new();
        if !(200..300).contains(&status) {
            // The body of a refusal is the message; keep a bounded prefix so
            // a 502 can name the origin the mirror could not reach.
            let mut collected = BytesMut::new();
            while collected.len() < ERROR_BODY_LIMIT {
                match body.frame().await {
                    None => break,
                    Some(Err(e)) => return Err(MirrorError::Transport(e)),
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            collected.extend_from_slice(&data);
                        }
                    }
                }
            }
            collected.truncate(ERROR_BODY_LIMIT);
            error_body = String::from_utf8_lossy(&collected).trim_end().to_string();
        }
        Ok(MirrorResponse {
            status,
            content_length,
            age,
            body: Some(body),
            error_body,
        })
    }
}

/// A [FetchUrl] over a GCS bucket URL, a plain HTTPS URL, or a path under
/// the mirror.
#[derive(Clone, Debug)]
pub enum AnyUrl {
    Https(ReqwestUrl),
    Gcs(GcsUrl),
    Mirror(MirrorUrl),
}

/// Join error for [AnyUrl].
#[derive(Debug)]
pub enum AnyJoinError {
    Https(url::ParseError),
    Gcs(()),
    Mirror(Infallible),
}

impl FetchUrl for AnyUrl {
    type JoinError = AnyJoinError;

    fn join(&self, input: &str) -> Result<Self, Self::JoinError> {
        match self {
            AnyUrl::Https(u) => u
                .join(input)
                .map(AnyUrl::Https)
                .map_err(AnyJoinError::Https),
            AnyUrl::Gcs(u) => u.join(input).map(AnyUrl::Gcs).map_err(AnyJoinError::Gcs),
            AnyUrl::Mirror(u) => u
                .join(input)
                .map(AnyUrl::Mirror)
                .map_err(AnyJoinError::Mirror),
        }
    }

    fn filename(&self) -> String {
        match self {
            AnyUrl::Https(u) => u.filename(),
            AnyUrl::Gcs(u) => u.filename(),
            AnyUrl::Mirror(u) => u.filename(),
        }
    }
}

/// A [FetchResponse] from either backend.
#[derive(Debug)]
pub enum AnyResponse {
    Https(Response),
    Gcs(Result<google_cloud_storage::read_object::ReadObjectResponse, GcsError>),
    Mirror(MirrorResponse),
}

/// Error from an [AnyResponse] (or from constructing an [AnyBackend]).
#[derive(Debug)]
pub enum AnyRespError {
    Https(ReqwestError),
    Gcs(GcsError),
    Mirror(MirrorError),
    /// The configured plain-HTTPS read URL could not be parsed.
    InvalidUrl(url::ParseError),
}

impl FetchResponse for AnyResponse {
    type Error = AnyRespError;

    fn error_for_status(self) -> Result<Self, Self::Error> {
        match self {
            AnyResponse::Https(r) => FetchResponse::error_for_status(r)
                .map(AnyResponse::Https)
                .map_err(AnyRespError::Https),
            AnyResponse::Gcs(r) => FetchResponse::error_for_status(r)
                .map(AnyResponse::Gcs)
                .map_err(AnyRespError::Gcs),
            AnyResponse::Mirror(r) => FetchResponse::error_for_status(r)
                .map(AnyResponse::Mirror)
                .map_err(AnyRespError::Mirror),
        }
    }

    fn is_success(&self) -> bool {
        match self {
            AnyResponse::Https(r) => FetchResponse::is_success(r),
            AnyResponse::Gcs(r) => FetchResponse::is_success(r),
            AnyResponse::Mirror(r) => FetchResponse::is_success(r),
        }
    }

    fn status_code(&self) -> usize {
        match self {
            AnyResponse::Https(r) => FetchResponse::status_code(r),
            AnyResponse::Gcs(r) => FetchResponse::status_code(r),
            AnyResponse::Mirror(r) => FetchResponse::status_code(r),
        }
    }

    fn content_length(&self) -> Option<u64> {
        match self {
            AnyResponse::Https(r) => FetchResponse::content_length(r),
            AnyResponse::Gcs(r) => FetchResponse::content_length(r),
            AnyResponse::Mirror(r) => FetchResponse::content_length(r),
        }
    }

    async fn bytes(self) -> Result<Bytes, Self::Error> {
        match self {
            AnyResponse::Https(r) => FetchResponse::bytes(r).await.map_err(AnyRespError::Https),
            AnyResponse::Gcs(r) => FetchResponse::bytes(r).await.map_err(AnyRespError::Gcs),
            AnyResponse::Mirror(r) => FetchResponse::bytes(r).await.map_err(AnyRespError::Mirror),
        }
    }

    async fn chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
        match self {
            AnyResponse::Https(r) => FetchResponse::chunk(r).await.map_err(AnyRespError::Https),
            AnyResponse::Gcs(r) => FetchResponse::chunk(r).await.map_err(AnyRespError::Gcs),
            AnyResponse::Mirror(r) => FetchResponse::chunk(r).await.map_err(AnyRespError::Mirror),
        }
    }

    fn generation(&self) -> Option<i64> {
        match self {
            AnyResponse::Https(r) => FetchResponse::generation(r),
            AnyResponse::Gcs(r) => FetchResponse::generation(r),
            AnyResponse::Mirror(r) => FetchResponse::generation(r),
        }
    }
}

/// A request for either backend. Both variants are boxed so the enum stays
/// small regardless of which backend's request type is larger
/// (clippy::large_enum_variant); a request is a transient per-fetch value.
#[derive(Debug)]
pub enum AnyRequest {
    Https(Box<Request>),
    Gcs(Box<google_cloud_storage::builder::storage::ReadObject>),
    Mirror(Box<MirrorRequest>),
}

/// A [FetchBackend] that is either the GCS client or a reqwest HTTPS client,
/// selected at construction. See the module note above. The GCS `Storage`
/// handle is boxed (it's far larger than a reqwest `Client`).
#[derive(Clone, Debug)]
pub enum AnyBackend {
    Https(Client),
    Gcs(Box<Storage>),
    Mirror(MirrorClient),
}

impl FetchBackend for AnyBackend {
    type Url = AnyUrl;
    type Request = AnyRequest;
    type Response = AnyResponse;

    fn get(
        &self,
        url: Self::Url,
    ) -> Result<Self::Request, <Self::Response as FetchResponse>::Error> {
        match (self, url) {
            (AnyBackend::Https(c), AnyUrl::Https(u)) => FetchBackend::get(c, u)
                .map(|r| AnyRequest::Https(Box::new(r)))
                .map_err(AnyRespError::Https),
            (AnyBackend::Gcs(s), AnyUrl::Gcs(u)) => FetchBackend::get(&**s, u)
                .map(|r| AnyRequest::Gcs(Box::new(r)))
                .map_err(AnyRespError::Gcs),
            (AnyBackend::Mirror(m), AnyUrl::Mirror(u)) => FetchBackend::get(m, u)
                .map(|r| AnyRequest::Mirror(Box::new(r)))
                .map_err(AnyRespError::Mirror),
            // A RemoteCache is always built with a matching backend+url pair
            // (see RemoteCache::new_any_*), so a mismatch is a construction bug.
            _ => unreachable!("AnyBackend: url does not match backend variant"),
        }
    }

    async fn execute(
        &self,
        req: Self::Request,
    ) -> Result<Self::Response, <Self::Response as FetchResponse>::Error> {
        match (self, req) {
            (AnyBackend::Https(c), AnyRequest::Https(r)) => FetchBackend::execute(c, *r)
                .await
                .map(AnyResponse::Https)
                .map_err(AnyRespError::Https),
            (AnyBackend::Gcs(s), AnyRequest::Gcs(r)) => FetchBackend::execute(&**s, *r)
                .await
                .map(AnyResponse::Gcs)
                .map_err(AnyRespError::Gcs),
            (AnyBackend::Mirror(m), AnyRequest::Mirror(r)) => FetchBackend::execute(m, *r)
                .await
                .map(AnyResponse::Mirror)
                .map_err(AnyRespError::Mirror),
            _ => unreachable!("AnyBackend: request does not match backend variant"),
        }
    }
}

#[cfg(test)]
mod any_backend_tests {
    use super::*;

    fn https(base: &str) -> AnyUrl {
        AnyUrl::Https(ReqwestUrl::try_from(base).unwrap())
    }
    fn gcs(object: &str) -> AnyUrl {
        AnyUrl::Gcs(GcsUrl {
            bucket: "projects/_/buckets/b".into(),
            object: object.into(),
        })
    }

    #[test]
    fn any_url_https_join_appends_segment() {
        let joined = https("https://cache.example.com/")
            .join("index.shisha")
            .unwrap();
        match &joined {
            AnyUrl::Https(u) => assert_eq!(u.0.as_str(), "https://cache.example.com/index.shisha"),
            other => panic!("expected Https, got {other:?}"),
        }
        assert_eq!(joined.filename(), "index.shisha");
    }

    #[test]
    fn any_url_https_join_requires_trailing_slash() {
        // Footgun: without a trailing slash on the base, Url::join replaces the
        // last path segment instead of appending under it. This is exactly why
        // the R2 / mirror base URL must end in `/`.
        let no_slash = https("https://cache.example.com/prefix")
            .join("a.zst")
            .unwrap();
        match &no_slash {
            AnyUrl::Https(u) => assert_eq!(u.0.as_str(), "https://cache.example.com/a.zst"),
            other => panic!("expected Https, got {other:?}"),
        }
        let with_slash = https("https://cache.example.com/prefix/")
            .join("a.zst")
            .unwrap();
        match &with_slash {
            AnyUrl::Https(u) => assert_eq!(u.0.as_str(), "https://cache.example.com/prefix/a.zst"),
            other => panic!("expected Https, got {other:?}"),
        }
    }

    #[test]
    fn any_url_gcs_join_and_filename() {
        let joined = gcs("").join("abc.zst").unwrap();
        match &joined {
            AnyUrl::Gcs(u) => assert_eq!(u.object, "abc.zst"),
            other => panic!("expected Gcs, got {other:?}"),
        }
        assert_eq!(joined.filename(), "abc.zst");
        // A nested join uses `/` separators; filename() returns the last segment.
        assert_eq!(gcs("dir").join("file.zst").unwrap().filename(), "file.zst");
    }

    #[test]
    fn any_backend_get_dispatches_to_https() {
        let backend = AnyBackend::Https(Client::new());
        let req = backend
            .get(https("https://cache.example.com/index.shisha"))
            .unwrap();
        assert!(matches!(req, AnyRequest::Https(_)));
    }

    #[test]
    #[should_panic(expected = "does not match backend")]
    fn any_backend_get_rejects_url_backend_mismatch() {
        // An HTTPS backend handed a GCS url is a construction bug -> panic,
        // never a silent wrong fetch.
        let backend = AnyBackend::Https(Client::new());
        let _ = backend.get(gcs("o"));
    }
}

#[cfg(test)]
mod mirror_backend_tests {
    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;

    /// Serves three paths on a Unix socket: a 200 with a body, a 404 with a
    /// body, and a 502 whose body is the mirror's refusal line.
    async fn serve(socket: std::path::PathBuf) {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|req: http::Request<Incoming>| async move {
                    let (status, body) = match req.uri().path() {
                        "/-/c/cache.example/-/index.shisha" => (200, "index-bytes"),
                        "/-/c/cache.example/-/stale.shisha" => (200, "old"),
                        "/boom" => (
                            502,
                            "the mirror could not reach https://cache.example/: down\n",
                        ),
                        _ => (404, "no such key"),
                    };
                    let mut response = http::Response::builder().status(status);
                    if req.uri().path().ends_with("stale.shisha") {
                        response = response.header(http::header::AGE, "120");
                    }
                    Ok::<_, Infallible>(
                        response
                            .body(Full::new(Bytes::from_static(body.as_bytes())))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }

    fn start() -> (tempfile::TempDir, MirrorEndpoint) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mirror.sock");
        tokio::spawn(serve(socket.clone()));
        (dir, MirrorEndpoint::Unix(socket))
    }

    async fn wait_for_socket(endpoint: &MirrorEndpoint) {
        let MirrorEndpoint::Unix(path) = endpoint else {
            unreachable!()
        };
        for _ in 0..50 {
            if tokio::net::UnixStream::connect(path).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("test mirror did not come up");
    }

    #[tokio::test]
    async fn get_through_the_socket_streams_the_body() {
        let (_dir, endpoint) = start();
        wait_for_socket(&endpoint).await;
        let origin = CacheOrigin::from_https_base("https://cache.example/").unwrap();
        let base = AnyUrl::Mirror(MirrorUrl::cache_mount(endpoint, &origin));
        let backend = AnyBackend::Mirror(MirrorClient::new());
        let req = backend.get(base.join("index.shisha").unwrap()).unwrap();
        let mut resp = backend.execute(req).await.unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.status_code(), 200);
        assert_eq!(resp.content_length(), Some(11));
        let mut got = Vec::new();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, b"index-bytes");
    }

    #[tokio::test]
    async fn a_refusal_body_becomes_the_error() {
        let (_dir, endpoint) = start();
        wait_for_socket(&endpoint).await;
        let backend = MirrorClient::new();
        let req = backend
            .get(MirrorUrl::new(endpoint.clone(), "/boom"))
            .unwrap();
        let resp = backend.execute(req).await.unwrap();
        assert_eq!(resp.status_code(), 502);
        let err = resp.error_for_status().unwrap_err();
        assert_eq!(
            err.to_string(),
            "the mirror could not reach https://cache.example/: down"
        );
        let req = backend.get(MirrorUrl::new(endpoint, "/nothing")).unwrap();
        let resp = backend.execute(req).await.unwrap();
        assert_eq!(resp.status_code(), 404);
        assert!(!resp.is_success());
    }

    #[tokio::test]
    async fn age_header_is_read_and_a_dead_socket_is_a_connect_error() {
        let (_dir, endpoint) = start();
        wait_for_socket(&endpoint).await;
        let backend = MirrorClient::new();
        let url = MirrorUrl::new(endpoint, "/-/c/cache.example/-/stale.shisha");
        let resp = backend.execute(backend.get(url).unwrap()).await.unwrap();
        assert_eq!(resp.age(), Some(120));
        assert_eq!(resp.bytes().await.unwrap(), Bytes::from_static(b"old"));

        let dead = MirrorEndpoint::Unix(std::path::PathBuf::from("/nonexistent/mirror.sock"));
        let err = backend
            .execute(backend.get(MirrorUrl::new(dead, "/x")).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, MirrorError::Connect { .. }), "{err}");
        assert!(
            err.to_string()
                .starts_with("the mirror at /nonexistent/mirror.sock did not answer: ")
        );
    }

    #[test]
    fn mirror_url_joins_like_an_https_base() {
        let endpoint = MirrorEndpoint::Unix(std::path::PathBuf::from("/s"));
        let origin = CacheOrigin::from_https_base("https://cache.example/").unwrap();
        let base = MirrorUrl::cache_mount(endpoint, &origin);
        assert_eq!(base.path, "/-/c/cache.example/-/");
        let obj = base.join("github.com/o/r/abc.closure.shisha").unwrap();
        assert_eq!(
            obj.path,
            "/-/c/cache.example/-/github.com/o/r/abc.closure.shisha"
        );
        assert_eq!(obj.filename(), "abc.closure.shisha");
        // Joining under a key, as Url::join would, replaces the last segment.
        assert_eq!(
            obj.join("x.zst").unwrap().path,
            "/-/c/cache.example/-/github.com/o/r/x.zst"
        );
        assert_eq!(
            base.join("/-/git/a/b/-/bundle").unwrap().path,
            "/-/git/a/b/-/bundle"
        );
    }
}
