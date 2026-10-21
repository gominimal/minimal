//! The HTTP/1.1 server: one accept loop per socket, the host socket taking
//! every request and the door socket reads alone (MIR-008, MIR-080).

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use common::mirror::MirrorPath;
use futures::TryStreamExt;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use crate::git::{Copy, Repos};
use crate::origin::{Origins, Served};
use crate::status::{Disk, OriginRow, Status};
use crate::store::Store;

/// The default budget until the disk rules land (MIR-040).
const DEFAULT_BUDGET_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// Which socket a request came in on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The host socket: the laptop's own processes.
    Host,
    /// A door: a guest daemon, reads only.
    Door,
}

/// Everything a request handler reaches.
pub struct Mirror {
    pub store: Store,
    pub origins: Origins,
    pub repos: Repos,
    pub dirs: mirror_client::MirrorDirs,
}

type Body = BoxBody<Bytes, std::io::Error>;

fn text(status: StatusCode, body: impl Into<String>) -> Response<Body> {
    let body: String = body.into();
    let mut response = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn not_found() -> Response<Body> {
    text(StatusCode::NOT_FOUND, "no such key\n")
}

fn unavailable(body: String) -> Response<Body> {
    text(StatusCode::BAD_GATEWAY, format!("{body}\n"))
}

async fn file_response(path: &Path, head_only: bool, age: Option<u64>) -> Response<Body> {
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "a held object could not be opened");
            return not_found();
        }
    };
    let len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "a held object could not be read");
            return not_found();
        }
    };
    let body: Body = if head_only {
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed()
    } else {
        StreamBody::new(ReaderStream::new(file).map_ok(Frame::data)).boxed()
    };
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, len.into());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    if let Some(age) = age {
        response.headers_mut().insert(header::AGE, age.into());
    }
    response
}

async fn status_document(mirror: &Mirror) -> Status {
    let store = mirror.store.clone();
    let used_bytes = tokio::task::spawn_blocking(move || store.used_bytes())
        .await
        .unwrap_or(0);
    Status {
        pid: std::process::id(),
        host_socket: mirror.dirs.host_socket().display().to_string(),
        door_socket: mirror.dirs.door_socket().display().to_string(),
        store: mirror.store.root().display().to_string(),
        origins: mirror
            .origins
            .status()
            .into_iter()
            .map(|(origin, s)| OriginRow {
                origin: origin.as_str().to_string(),
                last_contact: s.last_contact,
                last_failure: s.last_failure,
            })
            .collect(),
        disk: Disk {
            used_bytes,
            protected_bytes: 0,
            budget_bytes: DEFAULT_BUDGET_BYTES,
        },
        repositories: mirror.repos.status().await,
    }
}

/// Answers one request.
pub async fn handle(mirror: Arc<Mirror>, role: Role, request: Request<Incoming>) -> Response<Body> {
    let head_only = match *request.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => return text(StatusCode::METHOD_NOT_ALLOWED, "GET or HEAD only\n"),
    };
    if request.uri().query().is_some() {
        return not_found();
    }
    let path = request.uri().path().to_string();
    tracing::debug!(role = ?role, %path, head_only, "request");
    if path == "/-/status" {
        return match role {
            Role::Host => {
                let document = status_document(&mirror).await;
                let json = serde_json::to_string_pretty(&document).unwrap_or_default();
                let mut response = text(StatusCode::OK, json);
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("application/json"),
                );
                response
            }
            Role::Door => not_found(),
        };
    }
    match MirrorPath::parse(&path) {
        None => not_found(),
        Some(MirrorPath::CacheObject { origin, key }) => {
            match mirror.origins.get(&origin, &key).await {
                Served::File { path, age } => file_response(&path, head_only, age).await,
                Served::NotFound => not_found(),
                Served::Unavailable(body) => unavailable(body),
            }
        }
        Some(MirrorPath::GitBundle { slug }) => match mirror.repos.copy(&slug).await {
            Copy::Ready { bundle, .. } => file_response(&bundle, head_only, None).await,
            Copy::NoCopy(body) => unavailable(body),
        },
        Some(MirrorPath::GitPath { slug }) => match role {
            Role::Door => not_found(),
            Role::Host => match mirror.repos.copy(&slug).await {
                Copy::Ready { repo, .. } => text(StatusCode::OK, format!("{}\n", repo.display())),
                Copy::NoCopy(body) => unavailable(body),
            },
        },
        // The trusted root follows with the sync (MIR-006).
        Some(MirrorPath::TrustedRoot) => not_found(),
    }
}

/// Serves one socket until shutdown.
pub async fn serve(
    mirror: Arc<Mirror>,
    listener: UnixListener,
    role: Role,
    shutdown: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, ?role, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let mirror = mirror.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let mirror = mirror.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(mirror, role, request).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(error = %e, ?role, "connection ended");
            }
        });
    }
}
