//! The daemon against local origins: pull-through, absences, refusals, the
//! root index, HEAD, the door's limits, and repository copies.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use common::fetchers::{
    FetchBackend, FetchResponse, MirrorClient, MirrorEndpoint, MirrorRequest, MirrorUrl,
};
use common::mirror::{CacheOrigin, RepoSlug};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use minmirrord::git::Repos;
use minmirrord::origin::Origins;
use minmirrord::server::{Mirror, Role, serve};
use minmirrord::store::Store;
use sha2::Digest;
use tokio_util::sync::CancellationToken;

const ARTIFACT: &[u8] = b"artifact bytes";

struct Origin {
    port: u16,
    hits: Arc<AtomicUsize>,
    down: Arc<AtomicBool>,
}

/// A local origin on loopback that serves one artifact, one closure with one
/// companion, and a root index whose body changes with its ETag.
async fn start_origin() -> Origin {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let down = Arc::new(AtomicBool::new(false));
    let (hits2, down2) = (hits.clone(), down.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let hits = hits2.clone();
            let down = down2.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: http::Request<Incoming>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let down = down.load(Ordering::SeqCst);
                    async move {
                        let path = req.uri().path().to_string();
                        let sha = hex::encode(sha2::Sha256::digest(ARTIFACT));
                        // "Down" answers 503 on the pooled connection, which
                        // the mirror treats as an origin it cannot use.
                        let (status, body, etag) = if down {
                            (503, b"down".to_vec(), None)
                        } else if path == format!("/{sha}.zst") {
                            (200, ARTIFACT.to_vec(), None)
                        } else if path.ends_with("deadbeef.zst") {
                            (200, b"wrong bytes".to_vec(), None)
                        } else if path == "/index.shisha" {
                            if req
                                .headers()
                                .get("if-none-match")
                                .is_some_and(|v| v == "\"v1\"")
                            {
                                (304, Vec::new(), Some("\"v1\""))
                            } else {
                                (200, b"root-index".to_vec(), Some("\"v1\""))
                            }
                        } else if path.ends_with(".closure.shisha") {
                            (200, b"closure".to_vec(), None)
                        } else if path.ends_with(".map.json") {
                            (200, b"{}".to_vec(), None)
                        } else {
                            (404, b"nope".to_vec(), None)
                        };
                        let mut response = http::Response::builder().status(status);
                        if let Some(etag) = etag {
                            response = response.header("etag", etag);
                        }
                        Ok::<_, Infallible>(response.body(Full::new(Bytes::from(body))).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Origin { port, hits, down }
}

struct Daemon {
    _dir: tempfile::TempDir,
    store: Store,
    host: MirrorEndpoint,
    door: MirrorEndpoint,
}

async fn start_daemon(origin_base: String) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let dirs = mirror_client::MirrorDirs::new(dir.path().join("state"), dir.path().join("store"));
    std::fs::create_dir_all(&dirs.state).unwrap();
    let store = Store::new(dirs.store.clone());
    store.init().unwrap();
    let mirror = Arc::new(Mirror {
        origins: Origins::with_scheme(store.clone(), "http"),
        repos: Repos::with_origin_base(store.clone(), origin_base),
        store: store.clone(),
        dirs: dirs.clone(),
    });
    let host_listener = tokio::net::UnixListener::bind(dirs.host_socket()).unwrap();
    let door_listener = tokio::net::UnixListener::bind(dirs.door_socket()).unwrap();
    let token = CancellationToken::new();
    tokio::spawn(serve(
        mirror.clone(),
        host_listener,
        Role::Host,
        token.clone(),
    ));
    tokio::spawn(serve(mirror, door_listener, Role::Door, token));
    Daemon {
        host: MirrorEndpoint::Unix(dirs.host_socket()),
        door: MirrorEndpoint::Unix(dirs.door_socket()),
        store,
        _dir: dir,
    }
}

async fn get(endpoint: &MirrorEndpoint, path: &str) -> (usize, Bytes, Option<u64>) {
    let client = MirrorClient::new();
    let req = client.get(MirrorUrl::new(endpoint.clone(), path)).unwrap();
    let resp = client.execute(req).await.unwrap();
    let status = resp.status_code();
    let age = resp.age();
    let body = if status < 300 {
        resp.bytes().await.unwrap()
    } else {
        Bytes::from(resp.error_for_status().unwrap_err().to_string())
    };
    (status, body, age)
}

#[tokio::test]
async fn immutable_miss_fetches_stores_and_streams() {
    let origin = start_origin().await;
    let daemon = start_daemon(String::new()).await;
    let o = CacheOrigin::parse(&format!("127.0.0.1:{}", origin.port)).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(ARTIFACT));
    let path = format!("{}{sha}.zst", o.mount());
    let (status, body, _) = get(&daemon.host, &path).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], ARTIFACT);
    assert_eq!(origin.hits.load(Ordering::SeqCst), 1);
    // The second request is served from the store: the origin sees nothing.
    let (status, body, _) = get(&daemon.door, &path).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], ARTIFACT);
    assert_eq!(origin.hits.load(Ordering::SeqCst), 1);
    assert!(
        daemon
            .store
            .root()
            .join("c")
            .join(o.as_str())
            .join(format!("{sha}.zst"))
            .is_file()
    );
}

#[tokio::test]
async fn artifact_hash_mismatch_is_not_stored() {
    let origin = start_origin().await;
    let daemon = start_daemon(String::new()).await;
    let o = CacheOrigin::parse(&format!("127.0.0.1:{}", origin.port)).unwrap();
    let key = format!("{}deadbeef.zst", "0".repeat(56));
    let (status, body, _) = get(&daemon.host, &format!("{}{key}", o.mount())).await;
    assert_eq!(status, 502, "{body:?}");
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("does not match the name")
    );
    assert!(
        !daemon
            .store
            .root()
            .join("c")
            .join(o.as_str())
            .join(&key)
            .exists()
    );
    assert!(
        std::fs::read_dir(daemon.store.tmp_dir())
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn origin_absence_is_recorded_and_served_when_offline() {
    let origin = start_origin().await;
    let daemon = start_daemon(String::new()).await;
    let o = CacheOrigin::parse(&format!("127.0.0.1:{}", origin.port)).unwrap();
    let missing = format!("{}{}.zst", o.mount(), "a".repeat(64));
    let (status, _, _) = get(&daemon.host, &missing).await;
    assert_eq!(status, 404);
    let hits = origin.hits.load(Ordering::SeqCst);
    // Within a minute the record answers and the origin is not asked again.
    let (status, _, _) = get(&daemon.host, &missing).await;
    assert_eq!(status, 404);
    assert_eq!(origin.hits.load(Ordering::SeqCst), hits);
    // Offline, a key with no record is a 502 that names the origin.
    origin.down.store(true, Ordering::SeqCst);
    let other = format!("{}{}.zst", o.mount(), "b".repeat(64));
    let (status, body, _) = get(&daemon.host, &other).await;
    assert_eq!(status, 502);
    assert!(
        std::str::from_utf8(&body).unwrap().starts_with(&format!(
            "the mirror could not reach https://{}/: ",
            o.as_str()
        )),
        "{body:?}"
    );
    // And the recorded absence still answers 404.
    let (status, _, _) = get(&daemon.host, &missing).await;
    assert_eq!(status, 404);
    // A port nothing listens on is a connection failure: a 502 that names the
    // origin, and the host is left alone afterwards.
    let closed = CacheOrigin::parse("127.0.0.1:9").unwrap();
    let (status, body, _) = get(
        &daemon.host,
        &format!("{}{}.zst", closed.mount(), "c".repeat(64)),
    )
    .await;
    assert_eq!(status, 502);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .starts_with("the mirror could not reach https://127.0.0.1:9/: "),
        "{body:?}"
    );
}

#[tokio::test]
async fn root_index_revalidates_and_serves_stale_with_age_when_offline() {
    let origin = start_origin().await;
    let daemon = start_daemon(String::new()).await;
    let o = CacheOrigin::parse(&format!("127.0.0.1:{}", origin.port)).unwrap();
    let path = format!("{}index.shisha", o.mount());
    let (status, body, age) = get(&daemon.host, &path).await;
    assert_eq!((status, &body[..], age), (200, &b"root-index"[..], None));
    let hits = origin.hits.load(Ordering::SeqCst);
    // Fresh: no origin contact.
    let (status, _, _) = get(&daemon.host, &path).await;
    assert_eq!(status, 200);
    assert_eq!(origin.hits.load(Ordering::SeqCst), hits);
    // Age the held copy past its window: the next request revalidates and
    // the origin answers 304 to the stored ETag.
    let held = daemon
        .store
        .root()
        .join("c")
        .join(o.as_str())
        .join("index.shisha");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 60);
    std::fs::File::options()
        .append(true)
        .open(&held)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let (status, body, age) = get(&daemon.host, &path).await;
    assert_eq!((status, &body[..], age), (200, &b"root-index"[..], None));
    assert_eq!(origin.hits.load(Ordering::SeqCst), hits + 1);
    // Offline and past the window: the held copy comes back with its age.
    std::fs::File::options()
        .append(true)
        .open(&held)
        .unwrap()
        .set_modified(old)
        .unwrap();
    origin.down.store(true, Ordering::SeqCst);
    let (status, body, age) = get(&daemon.host, &path).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"root-index");
    assert!(age.is_some_and(|a| a >= 500), "{age:?}");
}

#[tokio::test]
async fn head_request_pulls_through_and_companions_follow_a_closure() {
    let origin = start_origin().await;
    let daemon = start_daemon(String::new()).await;
    let o = CacheOrigin::parse(&format!("127.0.0.1:{}", origin.port)).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(ARTIFACT));
    let client = MirrorClient::new();
    let url = MirrorUrl::new(daemon.host.clone(), format!("{}{sha}.zst", o.mount()));
    let resp = client.execute(MirrorRequest::head(url)).await.unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.content_length(), Some(ARTIFACT.len() as u64));
    assert!(
        daemon
            .store
            .root()
            .join("c")
            .join(o.as_str())
            .join(format!("{sha}.zst"))
            .is_file()
    );

    let commit = "c".repeat(40);
    let closure = format!(
        "{}github.com/gominimal/pkgs/{commit}.closure.shisha",
        o.mount()
    );
    let (status, body, _) = get(&daemon.host, &closure).await;
    assert_eq!((status, &body[..]), (200, &b"closure"[..]));
    let map = daemon
        .store
        .root()
        .join("c")
        .join(o.as_str())
        .join(format!("github.com/gominimal/pkgs/{commit}.map.json"));
    for _ in 0..100 {
        if map.is_file() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(map.is_file(), "the commit map companion was not kept");
}

#[tokio::test]
async fn paths_outside_the_grammar_and_control_through_a_door_are_404() {
    let origin = start_origin().await;
    let daemon = start_daemon(String::new()).await;
    for path in [
        "/index.shisha",
        "/-/c/x/-/nope",
        "/-/status?x=1",
        "/-/git/github.com/-/bundle",
    ] {
        let (status, _, _) = get(&daemon.host, path).await;
        assert_eq!(status, 404, "{path}");
    }
    assert_eq!(origin.hits.load(Ordering::SeqCst), 0);
    let (status, body, _) = get(&daemon.host, "/-/status").await;
    assert_eq!(status, 200);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("\"host_socket\"")
    );
    let (status, _, _) = get(&daemon.door, "/-/status").await;
    assert_eq!(status, 404);
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A local "origin" repository whose clone URL is `<base><slug>`.
fn local_origin(root: &Path, slug: &str) -> PathBuf {
    let repo = root.join(slug);
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a"), "a").unwrap();
    git(&repo, &["add", "a"]);
    git(&repo, &["commit", "-qm", "one"]);
    git(&repo, &["tag", "v1"]);
    repo
}

#[tokio::test]
async fn copy_served_to_host_as_a_path_and_to_guest_as_a_bundle() {
    let origins = tempfile::tempdir().unwrap();
    let base = format!("file://{}/", origins.path().display());
    let origin_repo = local_origin(origins.path(), "example.test/owner/repo");
    let daemon = start_daemon(base).await;
    let slug = RepoSlug::parse("example.test/owner/repo").unwrap();

    let (status, body, _) = get(&daemon.host, "/-/git/example.test/owner/repo/-/path").await;
    assert_eq!(status, 200, "{body:?}");
    let copy = PathBuf::from(std::str::from_utf8(&body).unwrap().trim());
    assert_eq!(copy, daemon.store.repo_git(&slug));
    assert!(copy.join("HEAD").is_file());
    // A host client clones from the path and keeps the original URL as its remote.
    let client = tempfile::tempdir().unwrap();
    git(
        client.path(),
        &["clone", "-q", "--bare", copy.to_str().unwrap(), "c.git"],
    );
    let head = git(&client.path().join("c.git"), &["rev-parse", "main"]);
    assert_eq!(head, git(&origin_repo, &["rev-parse", "main"]));

    // The door gets no path, only the bundle, which git reads as a remote.
    let (status, _, _) = get(&daemon.door, "/-/git/example.test/owner/repo/-/path").await;
    assert_eq!(status, 404);
    let (status, bundle, _) = get(&daemon.door, "/-/git/example.test/owner/repo/-/bundle").await;
    assert_eq!(status, 200);
    let bundle_path = client.path().join("repo.bundle");
    std::fs::write(&bundle_path, &bundle).unwrap();
    git(
        client.path(),
        &[
            "clone",
            "-q",
            "--bare",
            bundle_path.to_str().unwrap(),
            "b.git",
        ],
    );
    assert_eq!(
        git(&client.path().join("b.git"), &["rev-parse", "v1"]),
        head
    );

    // An origin the mirror cannot copy is a 502 that names it.
    let (status, body, _) = get(&daemon.host, "/-/git/example.test/owner/absent/-/path").await;
    assert_eq!(status, 502);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .starts_with("the mirror could not copy https://example.test/owner/absent: "),
        "{body:?}"
    );
}
