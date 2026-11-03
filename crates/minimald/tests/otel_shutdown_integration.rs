//! minimald's telemetry at shutdown, through the real binary (spec TEL-038,
//! TEL-011): the spans of work still alive at a `Shutdown` are exported, and a
//! collector that never answers costs the stop no more than its bounds
//! (runtime 2 s, then flush 5 s, in `main`).
//!
//! Each test runs `minimald run` against a fresh state dir under `/tmp` (the
//! SSH socket path must fit `sun_path`), with every ambient `OTEL_*`,
//! `MINIMAL_*`, `DO_NOT_TRACK` and `RUST_LOG` variable removed, asks it to
//! shut down over its socket, and reads what a stub collector received.
#![cfg(target_os = "linux")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers: a failed spawn, connect or RPC must fail the test loudly"
)]

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A stub OTLP/HTTP collector on 127.0.0.1. `answer`: reply 200 to every
/// request and keep its body; otherwise accept and never read or answer.
struct Collector {
    url: String,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn collector(answer: bool) -> Collector {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let kept = bodies.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in l.incoming() {
            let Ok(conn) = conn else { continue };
            if !answer {
                held.push(conn); // accepted, never read, never answered
                continue;
            }
            let kept = kept.clone();
            std::thread::spawn(move || serve(conn, &kept));
        }
    });
    Collector { url, bodies }
}

/// Answer each request on `conn` with an empty 200, keeping its body.
fn serve(conn: std::net::TcpStream, kept: &Mutex<Vec<Vec<u8>>>) {
    let Ok(mut w) = conn.try_clone() else { return };
    let mut r = std::io::BufReader::new(conn);
    loop {
        let mut len = 0usize;
        let mut line = String::new();
        let mut any = false;
        while r.read_line(&mut line).is_ok_and(|n| n > 0) {
            any = true;
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
            line.clear();
        }
        if !any {
            return;
        }
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        kept.lock().unwrap().push(body);
        let ok = b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\n\
                   content-length: 0\r\n\r\n";
        if w.write_all(ok).is_err() {
            return;
        }
    }
}

/// Accepts the daemon's host key (a fresh one per state dir).
struct Accept;

impl russh::client::Handler for Accept {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A `minimald run` on a fresh state dir, exporting to `endpoint` with the
/// spool off (so what reaches the collector is the export's alone).
struct Daemon {
    child: Child,
    sock: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start(endpoint: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("mdot")
            .tempdir_in("/tmp")
            .unwrap();
        let mut c = Command::new(env!("CARGO_BIN_EXE_minimald"));
        c.arg("--minimal-state-dir")
            .arg(dir.path().join("s"))
            .arg("--minimal-cache-dir")
            .arg(dir.path().join("c"))
            .arg("run");
        for (k, _) in std::env::vars_os() {
            let name = k.to_string_lossy();
            if name.starts_with("OTEL_")
                || name.starts_with("MINIMAL_")
                || name == "DO_NOT_TRACK"
                || name == "RUST_LOG"
            {
                c.env_remove(&k);
            }
        }
        c.env("MINIMAL_TELEMETRY", "1")
            .env("MINIMAL_OTEL_SPOOL", "0")
            .env("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = c.spawn().unwrap();
        let sock = dir.path().join("s/providers/local-minimald0/ssh.sock");
        let mut d = Self {
            child,
            sock,
            _dir: dir,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::os::unix::net::UnixStream::connect(&d.sock).is_err() {
            assert!(
                d.child.try_wait().unwrap().is_none(),
                "minimald exited before listening"
            );
            assert!(Instant::now() < deadline, "minimald never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
        d
    }

    /// An authenticated SSH connection to the daemon.
    async fn connect(&self) -> russh::client::Handle<Accept> {
        let stream = tokio::net::UnixStream::connect(&self.sock).await.unwrap();
        let config = Arc::new(russh::client::Config::default());
        let mut handle = russh::client::connect_stream(config, stream, Accept)
            .await
            .unwrap();
        assert!(handle.authenticate_none("test").await.unwrap().success());
        handle
    }

    /// Send `Shutdown` (forced) over a connection of its own and wait for
    /// the answer; returns when it came.
    async fn shut_down(&self) -> Instant {
        use minimald_rpc::OneshotSshRpc as _;
        let handle = self.connect().await;
        let mut channel = handle.channel_open_session().await.unwrap();
        channel
            .request_subsystem(true, minimald_rpc::Shutdown::NAME)
            .await
            .unwrap();
        channel
            .data_bytes(b"{\"force\":true}".to_vec())
            .await
            .unwrap();
        channel.eof().await.unwrap();
        let mut answer = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                answer.extend_from_slice(&data);
            }
        }
        assert!(!answer.is_empty(), "Shutdown was not answered");
        Instant::now()
    }

    /// Wait for the process to exit, at most `bound`; panics past it.
    fn exited_within(&mut self, bound: Duration) -> Instant {
        let deadline = Instant::now() + bound;
        loop {
            if self.child.try_wait().unwrap().is_some() {
                return Instant::now();
            }
            if Instant::now() > deadline {
                if let Err(e) = self.child.kill() {
                    eprintln!("could not kill minimald: {e}");
                }
                panic!("minimald did not exit within {bound:?} of its Shutdown");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Already gone, normally: then both fail, and that is fine.
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// How many exported spans are named `name`: occurrences of the OTLP
/// protobuf encoding of `Span.name` (field 5, length-delimited) with it.
fn spans_named(bodies: &[Vec<u8>], name: &str) -> usize {
    let mut field = vec![0x2a, u8::try_from(name.len()).unwrap()];
    field.extend_from_slice(name.as_bytes());
    bodies
        .iter()
        .map(|b| {
            b.windows(field.len())
                .filter(|w| *w == field.as_slice())
                .count()
        })
        .sum()
}

/// TEL-038 (patch 23): a span of a task still alive when `Shutdown` arrives is
/// exported: here the `conn` span of a client connection held open across
/// it, which the server's drain aborts after its grace (`SHUTDOWN_GRACE`).
///
/// What this does not pin: the order in `main` (runtime shutdown, then the
/// flush). Today the drain ends every connection inside `async_main`, so
/// the spans end before either step and the test passes with the two steps
/// swapped too (checked by hand); the order matters for a task that outlives
/// the drain, which no client can produce here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_open_at_shutdown_still_exports_its_span() {
    let col = collector(true);
    let mut d = Daemon::start(&col.url);
    let held = d.connect().await;
    d.shut_down().await;
    d.exited_within(Duration::from_secs(10));
    drop(held);
    let bodies = col.bodies.lock().unwrap();
    // `start`'s readiness probe, the `Shutdown` client, the held client.
    assert_eq!(
        spans_named(&bodies, "conn"),
        3,
        "every connection's span is exported, the one still open at the \
         shutdown included"
    );
}

/// TEL-011: against a collector that accepts and never answers,
/// minimald exits within its shutdown bounds (runtime 2 s, then flush 5 s)
/// of answering `Shutdown`, plus slack, instead of waiting out the export.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_collector_does_not_hold_the_daemons_exit() {
    let col = collector(false);
    let mut d = Daemon::start(&col.url);
    let answered = d.shut_down().await;
    let exited = d.exited_within(Duration::from_secs(15));
    let took = exited.duration_since(answered);
    assert!(
        took < Duration::from_secs(2 + 5 + 1),
        "minimald took {took:?} to exit after Shutdown against a silent collector"
    );
    drop(col);
}
