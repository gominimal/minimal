//! Abstractions over reading data from the network.

use bytes::{Bytes, BytesMut};
use futures::future::FutureExt;
use google_cloud_storage::Error as GcsError;
use google_cloud_storage::client::Storage;
use reqwest::{Client, Error as ReqwestError, Request, Response, Url as UpstreamReqwestUrl};

use std::future::Future;

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

/// A [FetchUrl] over either a GCS bucket URL or a plain HTTPS URL.
#[derive(Clone, Debug)]
pub enum AnyUrl {
    Https(ReqwestUrl),
    Gcs(GcsUrl),
}

/// Join error for [AnyUrl].
#[derive(Debug)]
pub enum AnyJoinError {
    Https(url::ParseError),
    Gcs(()),
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
        }
    }

    fn filename(&self) -> String {
        match self {
            AnyUrl::Https(u) => u.filename(),
            AnyUrl::Gcs(u) => u.filename(),
        }
    }
}

/// A [FetchResponse] from either backend.
#[derive(Debug)]
pub enum AnyResponse {
    Https(Response),
    Gcs(Result<google_cloud_storage::read_object::ReadObjectResponse, GcsError>),
}

/// Error from an [AnyResponse] (or from constructing an [AnyBackend]).
#[derive(Debug)]
pub enum AnyRespError {
    Https(ReqwestError),
    Gcs(GcsError),
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
        }
    }

    fn is_success(&self) -> bool {
        match self {
            AnyResponse::Https(r) => FetchResponse::is_success(r),
            AnyResponse::Gcs(r) => FetchResponse::is_success(r),
        }
    }

    fn status_code(&self) -> usize {
        match self {
            AnyResponse::Https(r) => FetchResponse::status_code(r),
            AnyResponse::Gcs(r) => FetchResponse::status_code(r),
        }
    }

    fn content_length(&self) -> Option<u64> {
        match self {
            AnyResponse::Https(r) => FetchResponse::content_length(r),
            AnyResponse::Gcs(r) => FetchResponse::content_length(r),
        }
    }

    async fn bytes(self) -> Result<Bytes, Self::Error> {
        match self {
            AnyResponse::Https(r) => FetchResponse::bytes(r).await.map_err(AnyRespError::Https),
            AnyResponse::Gcs(r) => FetchResponse::bytes(r).await.map_err(AnyRespError::Gcs),
        }
    }

    async fn chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
        match self {
            AnyResponse::Https(r) => FetchResponse::chunk(r).await.map_err(AnyRespError::Https),
            AnyResponse::Gcs(r) => FetchResponse::chunk(r).await.map_err(AnyRespError::Gcs),
        }
    }

    fn generation(&self) -> Option<i64> {
        match self {
            AnyResponse::Https(r) => FetchResponse::generation(r),
            AnyResponse::Gcs(r) => FetchResponse::generation(r),
        }
    }
}

/// A request for either backend.
#[derive(Debug)]
pub enum AnyRequest {
    Https(Request),
    Gcs(google_cloud_storage::builder::storage::ReadObject),
}

/// A [FetchBackend] that is either the GCS client or a reqwest HTTPS client,
/// selected at construction. See the module note above.
#[derive(Clone, Debug)]
pub enum AnyBackend {
    Https(Client),
    Gcs(Storage),
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
                .map(AnyRequest::Https)
                .map_err(AnyRespError::Https),
            (AnyBackend::Gcs(s), AnyUrl::Gcs(u)) => FetchBackend::get(s, u)
                .map(AnyRequest::Gcs)
                .map_err(AnyRespError::Gcs),
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
            (AnyBackend::Https(c), AnyRequest::Https(r)) => FetchBackend::execute(c, r)
                .await
                .map(AnyResponse::Https)
                .map_err(AnyRespError::Https),
            (AnyBackend::Gcs(s), AnyRequest::Gcs(r)) => FetchBackend::execute(s, r)
                .await
                .map(AnyResponse::Gcs)
                .map_err(AnyRespError::Gcs),
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
