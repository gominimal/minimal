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
}

impl FetchUrl for ReqwestUrl {
    type JoinError = url::ParseError;

    fn join(&self, input: &str) -> Result<Self, Self::JoinError> {
        UpstreamReqwestUrl::join(&self.0, input).map(ReqwestUrl)
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
}

impl FetchResponse for Result<google_cloud_storage::read_object::ReadObjectResponse, GcsError> {
    type Error = GcsError;

    fn is_success(&self) -> bool {
        self.is_ok()
    }
    fn error_for_status(self) -> Result<Self, Self::Error> {
        Ok(self)
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
