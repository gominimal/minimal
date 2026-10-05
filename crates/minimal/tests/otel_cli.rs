//! The `min` binary's telemetry against a real (in-process) minimald: the
//! caller's trace crosses into the CLI and on to the daemon (TEL-021), ambient
//! `OTEL_*` alone exports nothing (TEL-001), and a collector that never answers
//! costs a command little and prints nothing (TEL-010, TEL-012).
//!
//! The daemon runs in this test process, so a [`SpanLog`] installed as the
//! process's subscriber sees its spans (process-wide, not `set_default`: a
//! thread-local subscriber in one of several parallel libtest threads can
//! miss callsites another thread registered first); a test picks its own
//! spans out by the trace id it sent. The CLI runs as
//! a child process whose environment starts with every `OTEL_*`,
//! `MINIMAL_*`, `DO_NOT_TRACK`, `TRACEPARENT` and `RUST_LOG` variable
//! removed, and writes its spans to a spool the test reads.
#![cfg(target_os = "linux")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers: a failed spawn or a malformed spool must fail the test loudly; \
              serde_json Value indexing returns Null for a missing key"
)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use minimal::GlobalArgs;
use minimald::test_harness::SpanLog;
use serde_json_lenient::Value;
use tracing_subscriber::layer::SubscriberExt as _;

// Each test that finds the daemon's spans by trace id in the process-wide
// [`SpanLog`] uses a trace id of its own: under libtest the tests share
// one process, and a shared id would let one test see another's spans.
const PARENT: &str = "b7ad6b7169203331";

/// Runs the compiled `min` against the harness daemon with a stripped
/// telemetry environment plus `env`; returns its output and wall time.
async fn run_min_env(
    args: &GlobalArgs,
    env: &[(&str, &str)],
    extra: &[&str],
) -> (std::process::Output, Duration) {
    let minimal_dir = args.minimal_dir.as_ref().unwrap();
    let config_dir = tempfile::TempDir::new().unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_min"));
    command
        .args(["--minimal-dir".as_ref(), minimal_dir.as_os_str()])
        .args(["--config-dir".as_ref(), config_dir.path().as_os_str()])
        .arg("--no-input")
        .args(extra);
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if name.starts_with("OTEL_")
            || name.starts_with("MINIMAL_")
            || name == "DO_NOT_TRACK"
            || name == "TRACEPARENT"
            || name == "RUST_LOG"
        {
            command.env_remove(&k);
        }
    }
    command.envs(env.iter().copied());
    let t = Instant::now();
    let out = command.output().await.unwrap();
    (out, t.elapsed())
}

/// A temporary directory with mode 0700: the spool refuses a directory
/// with group or other bits, and `tempfile` creates its directories with
/// the umask's default (0755).
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

/// Every span in the spool files under `dir`.
fn spool_spans(dir: &Path) -> Vec<Value> {
    let mut spans = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        for l in std::fs::read_to_string(&p).unwrap().lines() {
            let v: Value = serde_json_lenient::from_str(l).unwrap();
            for rs in v["resourceSpans"].as_array().into_iter().flatten() {
                for ss in rs["scopeSpans"].as_array().into_iter().flatten() {
                    spans.extend(ss["spans"].as_array().into_iter().flatten().cloned());
                }
            }
        }
    }
    spans
}

/// The process-wide [`SpanLog`], installed on first use.
fn span_log() -> SpanLog {
    static LOG: std::sync::OnceLock<SpanLog> = std::sync::OnceLock::new();
    LOG.get_or_init(|| {
        let log = SpanLog::default();
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(log.clone()))
            .unwrap();
        log
    })
    .clone()
}

fn named<'a>(spans: &'a [Value], name: &str) -> &'a Value {
    spans
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no {name} span in {spans:#?}"))
}

/// A loopback listener that accepts and never answers: a collector gone
/// silent. Returns its URL and a count of the connections it accepted.
fn tarpit() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for c in l.incoming() {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(c); // accepted, never read, never answered
        }
    });
    (url, accepted)
}

/// TEL-021 across both process boundaries: `min ls` run inside
/// a caller's trace (`TRACEPARENT`) records its `cmd` span as the caller's
/// child and `client.rpc` under it, and the daemon's `rpc` spans for its
/// calls are the `cmd` span's children (the CLI sends one context per
/// process), all in the caller's trace.
#[tokio::test]
async fn a_traced_min_ls_joins_the_callers_trace() {
    const TRACE: &str = "0af7651916cd43dd8448eb211c803101";
    let log = span_log();
    let (_daemon, args) = common::setup().await;
    let spool = private_tempdir();
    let tp = format!("00-{TRACE}-{PARENT}-01");
    let (out, _) = run_min_env(
        &args,
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", spool.path().to_str().unwrap()),
            ("TRACEPARENT", &tp),
        ],
        &["ls"],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let spans = spool_spans(spool.path());
    let cmd = named(&spans, "cmd");
    assert_eq!(cmd["traceId"], TRACE);
    assert_eq!(cmd["parentSpanId"], PARENT);
    let rpc = named(&spans, "client.rpc");
    assert_eq!(rpc["traceId"], TRACE);
    assert_eq!(rpc["parentSpanId"], cmd["spanId"], "client.rpc under cmd");

    // `min ls` asks the version, then lists.
    let served = log.find("rpc", "trace_id", TRACE);
    let names: Vec<_> = served.iter().filter_map(|s| s.field("rpc")).collect();
    assert_eq!(
        names,
        ["minimald-v1-GetVersion", "minimald-v1-ListSessions"],
        "{served:?}"
    );
    for s in &served {
        assert_eq!(
            s.field("parent_span_id"),
            cmd["spanId"].as_str(),
            "the daemon's rpc span is the CLI's cmd span's child: {s:?}"
        );
    }
}

/// (code review) `min` with its telemetry off (`DO_NOT_TRACK=1` here; not
/// opting in, or `OTEL_SDK_DISABLED`, decide the same) tells the daemon so
/// on every channel and sends no `TRACEPARENT`, even with one inherited:
/// the daemon's `rpc` spans for its calls are marked `telemetry=opt-out`,
/// have no parent, and none carries the inherited trace id. That the
/// daemon exports nothing of them is minimald's
/// `an_opted_out_request_leaves_no_daemon_span`.
#[tokio::test]
async fn an_opted_out_min_sends_no_traceparent_and_its_daemon_spans_are_marked() {
    const INHERITED: &str = "0af7651916cd43dd8448eb211c80319d";
    let log = span_log();
    let (_daemon, args) = common::setup().await;
    let spool = private_tempdir();
    let tp = format!("00-{INHERITED}-{PARENT}-01");
    let (out, _) = run_min_env(
        &args,
        &[
            ("DO_NOT_TRACK", "1"),
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", spool.path().to_str().unwrap()),
            ("TRACEPARENT", &tp),
        ],
        &["ls"],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        spool_spans(spool.path()).is_empty(),
        "DO_NOT_TRACK: the CLI itself spools nothing"
    );
    assert!(
        log.find("rpc", "trace_id", INHERITED).is_empty(),
        "no daemon span joined the inherited trace: {:?}",
        log.find("rpc", "trace_id", INHERITED)
    );
    let marked = log.find("rpc", "telemetry", "opt-out");
    assert!(
        marked
            .iter()
            .any(|s| s.field("rpc") == Some("minimald-v1-ListSessions")),
        "the listing's rpc span is marked opted out: {marked:?}"
    );
    for s in &marked {
        assert_eq!(
            s.field("parent_span_id"),
            None,
            "no TRACEPARENT was sent: {s:?}"
        );
    }
}

/// TEL-001: an ambient OTLP endpoint (a developer's shell, a CI
/// runner) without `MINIMAL_TELEMETRY=1` opens no connection to it and
/// spools nothing.
#[tokio::test]
async fn ambient_otel_alone_opens_no_connection() {
    let (_daemon, args) = common::setup().await;
    let (url, accepted) = tarpit();
    let spool = private_tempdir();
    let dir = spool.path().join("spool");
    let (out, _) = run_min_env(
        &args,
        &[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", &url),
            ("OTEL_TRACES_EXPORTER", "otlp"),
            ("MINIMAL_OTEL_SPOOL_DIR", dir.to_str().unwrap()),
        ],
        &["ls"],
    )
    .await;
    assert!(out.status.success());
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!dir.exists(), "nothing spooled");
}

/// TEL-010, TEL-012: against a collector that
/// accepts and never answers, `min ls` takes little longer than with
/// telemetry off (it took 2 s longer before the CLI's exit flush was
/// bounded) and prints none of the SDK's export errors.
///
/// Each side is the fastest of [`RUNS`] interleaved runs, so one run slowed
/// by a loaded host does not decide the comparison. The allowance is the
/// exit wait's bound (TEL-010, TEL-N01: `CLI_EXIT_FLUSH` plus 250 ms) with
/// as much again for scheduling: a silent collector that blocked the exit
/// past its bound still fails, by the 2 s it once cost.
#[tokio::test]
async fn a_silent_collector_costs_min_ls_little_and_prints_nothing() {
    const RUNS: usize = 3;
    let allowance = (mlog::otel::CLI_EXIT_FLUSH + Duration::from_millis(250)) * 2;
    let (_daemon, args) = common::setup().await;
    let (url, _accepted) = tarpit();
    let spool = private_tempdir();
    let (mut off, mut on) = (Duration::MAX, Duration::MAX);
    for _ in 0..RUNS {
        let (control, took) = run_min_env(&args, &[], &["ls"]).await;
        assert!(control.status.success());
        off = off.min(took);
        let (out, took) = run_min_env(
            &args,
            &[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", &url),
                ("MINIMAL_OTEL_SPOOL_DIR", spool.path().to_str().unwrap()),
            ],
            &["ls"],
        )
        .await;
        assert!(out.status.success());
        on = on.min(took);
        let stderr = String::from_utf8_lossy(&out.stderr);
        for noise in ["opentelemetry", "OTLP", "BatchSpanProcessor", "ERROR"] {
            assert!(!stderr.contains(noise), "{noise} on stderr: {stderr}");
        }
    }
    assert!(
        on < off + allowance,
        "min ls took at best {on:?} against a silent collector, {off:?} with \
         telemetry off ({RUNS} runs each; allowance {allowance:?})"
    );
}

// ---- plan T7 and T11: the join tests ----

/// One span as the collector received it, from the OTLP/protobuf body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SentSpan {
    name: String,
    trace_id: String,
    span_id: String,
    parent_span_id: String,
}

/// The fields of one protobuf message: `(field number, value)`, where a
/// length-delimited value is its bytes and the other wire types are
/// skipped. Enough to walk an `ExportTraceServiceRequest`.
fn proto_fields(mut b: &[u8]) -> Vec<(u64, &[u8])> {
    fn varint(b: &mut &[u8]) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = b.split_first()?;
            *b = rest;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    let mut out = Vec::new();
    while let Some(key) = varint(&mut b) {
        let skip = match key & 7 {
            0 => {
                varint(&mut b);
                continue;
            }
            1 => 8,
            5 => 4,
            2 => {
                let len = usize::try_from(varint(&mut b).unwrap()).unwrap();
                let (v, rest) = b.split_at(len);
                out.push((key >> 3, v));
                b = rest;
                continue;
            }
            w => panic!("wire type {w} in an OTLP body"),
        };
        b = &b[skip..];
    }
    out
}

/// Every span in the trace requests (`/v1/traces`) `col` received.
fn sent_spans(col: &Collector) -> Vec<SentSpan> {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut spans = Vec::new();
    for (path, body) in col.requests.lock().unwrap().iter() {
        if !path.ends_with("/v1/traces") {
            continue;
        }
        for (_, rs) in proto_fields(body).into_iter().filter(|f| f.0 == 1) {
            for (_, ss) in proto_fields(rs).into_iter().filter(|f| f.0 == 2) {
                for (_, span) in proto_fields(ss).into_iter().filter(|f| f.0 == 2) {
                    let mut s = SentSpan {
                        name: String::new(),
                        trace_id: String::new(),
                        span_id: String::new(),
                        parent_span_id: String::new(),
                    };
                    for (n, v) in proto_fields(span) {
                        match n {
                            1 => s.trace_id = hex(v),
                            2 => s.span_id = hex(v),
                            4 => s.parent_span_id = hex(v),
                            5 => s.name = String::from_utf8_lossy(v).into_owned(),
                            _ => {}
                        }
                    }
                    spans.push(s);
                }
            }
        }
    }
    spans
}

/// The same four fields for every span in the spool files under `dir`.
fn spooled_spans(dir: &Path) -> Vec<SentSpan> {
    spool_spans(dir)
        .iter()
        .map(|s| SentSpan {
            name: s["name"].as_str().unwrap_or_default().to_owned(),
            trace_id: s["traceId"].as_str().unwrap_or_default().to_owned(),
            span_id: s["spanId"].as_str().unwrap_or_default().to_owned(),
            parent_span_id: s["parentSpanId"].as_str().unwrap_or_default().to_owned(),
        })
        .collect()
}

/// A stub OTLP/HTTP collector on 127.0.0.1: answers every request with an
/// empty 200 and keeps its path and body.
struct Collector {
    url: String,
    requests: Requests,
}

/// Each request a [`Collector`] received: its path and body.
type Requests = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

fn collector() -> Collector {
    use std::io::{BufRead as _, Read as _, Write as _};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let requests: Requests = std::sync::Arc::default();
    let kept = requests.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(conn) = conn else { continue };
            let kept = kept.clone();
            std::thread::spawn(move || {
                let Ok(mut w) = conn.try_clone() else { return };
                let mut r = std::io::BufReader::new(conn);
                loop {
                    let mut request = String::new();
                    if r.read_line(&mut request).unwrap_or(0) == 0 {
                        return;
                    }
                    let path = request.split(' ').nth(1).unwrap_or_default().to_owned();
                    let mut len = 0usize;
                    let mut line = String::new();
                    while r.read_line(&mut line).is_ok_and(|n| n > 0) {
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        line.clear();
                    }
                    let mut body = vec![0; len];
                    if r.read_exact(&mut body).is_err() {
                        return;
                    }
                    kept.lock().unwrap().push((path, body));
                    let ok = b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\n\
                               content-length: 0\r\n\r\n";
                    if w.write_all(ok).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Collector { url, requests }
}

/// Plan T7 (spec 25 TEL-002, TEL-005, TEL-021, TEL-022): `MINIMAL_TELEMETRY=1
/// min ls` against a local collector. The CLI's `cmd` span reaches the
/// collector as a root (no caller's trace here: the CLI starts one), the
/// daemon's `rpc` spans for the version check and the listing are that
/// `cmd` span's children in the same trace, and the spool holds the very
/// records the collector got: the same spans, the same ids.
///
/// The daemon is the test harness's, in this process, with no exporter of
/// its own: its spans are read from the process's subscriber by the trace
/// id. minimald's own export to a collector is `otel_shutdown_integration`.
#[tokio::test]
async fn a_traced_min_ls_lands_in_one_trace_and_in_the_spool() {
    let log = span_log();
    let (_daemon, args) = common::setup().await;
    let col = collector();
    let spool = private_tempdir();
    let (out, _) = run_min_env(
        &args,
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", &col.url),
            ("MINIMAL_OTEL_SPOOL_DIR", spool.path().to_str().unwrap()),
        ],
        &["ls"],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut sent = sent_spans(&col);
    let cmd = sent
        .iter()
        .find(|s| s.name == "cmd")
        .unwrap_or_else(|| panic!("no cmd span at the collector: {sent:#?}"))
        .clone();
    assert_eq!(cmd.parent_span_id, "", "the CLI started the trace: {cmd:?}");
    assert!(
        sent.iter()
            .any(|s| s.name == "client.rpc" && s.parent_span_id == cmd.span_id),
        "{sent:#?}"
    );
    assert!(
        sent.iter().all(|s| s.trace_id == cmd.trace_id),
        "one trace: {sent:#?}"
    );

    let served = log.find("rpc", "trace_id", &cmd.trace_id);
    let names: Vec<_> = served.iter().filter_map(|s| s.field("rpc")).collect();
    assert_eq!(
        names,
        ["minimald-v1-GetVersion", "minimald-v1-ListSessions"],
        "{served:?}"
    );
    for s in &served {
        assert_eq!(
            s.field("parent_span_id"),
            Some(cmd.span_id.as_str()),
            "the daemon's rpc span is the cmd span's child: {s:?}"
        );
    }

    let mut spooled = spooled_spans(spool.path());
    sent.sort();
    spooled.sort();
    assert_eq!(sent, spooled, "the spool holds what the collector got");
}

/// Every span the daemon recorded in `trace`.
fn in_trace(log: &SpanLog, trace: &str) -> Vec<minimald::test_harness::LoggedSpan> {
    log.spans()
        .into_iter()
        .filter(|s| s.field("trace_id") == Some(trace))
        .collect()
}

/// A session of the harness daemon, named `name`, whose project declares
/// the task `tp`, which prints the `TRACEPARENT` its box was given
/// (`TP=none` without one) where a box can start.
async fn session_with_tp_task(daemon: &common::TestDaemon, name: &str) -> String {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, FinalizeSession,
        FinalizeSessionRequest,
    };
    let mut client = daemon.server.connect().await;
    let id = client
        .call::<CreateSession>(&minimald::test_harness::create_session_req(name, "/tmp"))
        .await
        .unwrap()
        .id;
    daemon.server.seed_workspace_mfile(id, TP_TASK_MFILE).await;
    minimald::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        minimald_rpc::Errorable::Ok(_) => {}
        minimald_rpc::Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
    id.to_string()
}

const TP_TASK_MFILE: &str = "[tasks.tp]\nbash = \"echo TP=${TRACEPARENT:-none}\"\n";
const TP_SHELL: &str = "echo TP=${TRACEPARENT:-none}";

/// `min` on a pseudo-terminal (`script(1)`; `min session attach` refuses
/// a stdin that is not a TTY), with `stdin` written to it and then closed,
/// as [`run_min_env`] otherwise.
async fn run_min_tty(
    args: &GlobalArgs,
    env: &[(&str, &str)],
    extra: &[&str],
    stdin: &[u8],
) -> std::process::Output {
    use tokio::io::AsyncWriteExt as _;
    let minimal_dir = args.minimal_dir.as_ref().unwrap();
    let config_dir = tempfile::TempDir::new().unwrap();
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let mut line = vec![
        quote(env!("CARGO_BIN_EXE_min")),
        "--minimal-dir".to_owned(),
        quote(minimal_dir.to_str().unwrap()),
        "--config-dir".to_owned(),
        quote(config_dir.path().to_str().unwrap()),
    ];
    line.extend(extra.iter().map(|a| quote(a)));
    let mut command = tokio::process::Command::new("script");
    command
        .args(["-qec", &line.join(" "), "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if name.starts_with("OTEL_")
            || name.starts_with("MINIMAL_")
            || name == "DO_NOT_TRACK"
            || name == "TRACEPARENT"
            || name == "RUST_LOG"
        {
            command.env_remove(&k);
        }
    }
    command.envs(env.iter().copied());
    let mut child = command.spawn().unwrap();
    let mut pipe = child.stdin.take().unwrap();
    pipe.write_all(stdin).await.unwrap();
    drop(pipe);
    tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("min exits")
        .unwrap()
}

/// One verb's run: its `min`'s output and the `cmd` span from its own spool.
struct VerbRun {
    verb: &'static str,
    out: std::process::Output,
    cmd: Option<SentSpan>,
}

/// The four session verbs, each run as its own `min` with `env` and a
/// spool of its own: `min session exec`, `min session run`, `min session
/// attach` (its shell fed on stdin) and `min task run` (a task session of
/// its own).
async fn run_the_verbs(
    daemon: &common::TestDaemon,
    args: &GlobalArgs,
    env: &[(&str, &str)],
) -> Vec<VerbRun> {
    static SESSIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SESSIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let session = session_with_tp_task(daemon, &format!("t11-{n}")).await;
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(project.path().join("minimal.toml"), TP_TASK_MFILE).unwrap();
    let project_dir = project.path().to_str().unwrap().to_owned();
    let mut runs = Vec::new();
    for verb in ["exec", "run", "attach", "task run"] {
        let spool = private_tempdir();
        let mut env: Vec<(&str, &str)> = env
            .iter()
            .copied()
            .filter(|(k, _)| *k != "MINIMAL_OTEL_SPOOL_DIR")
            .collect();
        env.push(("MINIMAL_OTEL_SPOOL_DIR", spool.path().to_str().unwrap()));
        let out = match verb {
            "exec" => {
                run_min_env(args, &env, &["session", "exec", &session, TP_SHELL])
                    .await
                    .0
            }
            "run" => {
                run_min_env(args, &env, &["session", "run", &session, "tp"])
                    .await
                    .0
            }
            "attach" => {
                run_min_tty(
                    args,
                    &env,
                    &["session", "attach", &session],
                    format!("{TP_SHELL}\nexit\n").as_bytes(),
                )
                .await
            }
            _ => {
                run_min_env(args, &env, &["-C", &project_dir, "task", "run", "tp"])
                    .await
                    .0
            }
        };
        let cmd = spooled_spans(spool.path())
            .into_iter()
            .find(|s| s.name == "cmd");
        runs.push(VerbRun { verb, out, cmd });
    }
    runs
}

/// Plan T11 (spec 25 TEL-021, TEL-022, TEL-025, TEL-045): run `min session
/// exec`, `min session run`, `min session attach` and `min task run` with
/// telemetry on inside a caller's trace. Each `min`'s `cmd` span joins
/// that trace at the collector and in the spool alike, and the daemon's
/// span for each verb's request (`exec` for exec, run and task run,
/// `attach` for attach) is that `cmd` span's child in the same trace. A
/// nested `min` given the `TRACEPARENT` that names the exec's daemon span
/// (what the daemon hands the box once that span is exported, TEL-023)
/// continues the trace as that span's child. With telemetry off
/// (`DO_NOT_TRACK=1`, a caller's `TRACEPARENT` inherited) nothing crosses:
/// nothing is sent or spooled, every verb's daemon span is marked
/// `telemetry=opt-out`, and none joins the inherited trace.
///
/// What needs more than this in-process harness, and where it is proved:
/// the harness has no packages, so no verb's box process starts (each
/// request is refused at the spawn, after its span); and its daemon has no
/// exporter, so it hands a box no `TRACEPARENT` (`box_traceparent`). That
/// a box gets the value only on opt-in is TEL-023's unit tests
/// (`an_unrecorded_exec_span_gives_the_box_no_traceparent`); a `min` inside
/// a box joining through the in-box helper is minimald's
/// `a_min_in_a_box_joins_the_outer_trace_through_the_helper_prefix`; and
/// the whole path on a real VM is lab scenario 715h.
#[tokio::test]
async fn exec_run_attach_and_task_run_share_the_commands_trace() {
    const TRACE: &str = "0af7651916cd43dd8448eb211c803111";
    let log = span_log();
    let (daemon, args) = common::setup().await;
    let col = collector();
    let tp = format!("00-{TRACE}-{PARENT}-01");
    let on = [
        ("MINIMAL_TELEMETRY", "1"),
        ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", col.url.as_str()),
        ("TRACEPARENT", tp.as_str()),
    ];
    let runs = run_the_verbs(&daemon, &args, &on).await;
    let sent = sent_spans(&col);
    let daemon_spans = in_trace(&log, TRACE);
    let mut exec_span_id = None;
    for r in &runs {
        let cmd = r.cmd.as_ref().unwrap_or_else(|| {
            panic!(
                "{}: no cmd span spooled; stderr: {}",
                r.verb,
                String::from_utf8_lossy(&r.out.stderr)
            )
        });
        assert_eq!(cmd.trace_id, TRACE, "{}: {cmd:?}", r.verb);
        assert_eq!(cmd.parent_span_id, PARENT, "{}: {cmd:?}", r.verb);
        assert!(
            sent.contains(cmd),
            "{}: the collector has the spooled cmd span: {sent:#?}",
            r.verb
        );
        let (name, command) = match r.verb {
            "exec" => ("exec", Some("min://shell ")),
            "run" => ("exec", Some("min://task/run tp")),
            "task run" => ("exec", Some("min://task/run --owns-box tp")),
            _ => ("attach", None),
        };
        let request = daemon_spans
            .iter()
            .find(|s| {
                s.name == name
                    && s.field("parent_span_id") == Some(cmd.span_id.as_str())
                    && command.is_none_or(|c| s.field("command").is_some_and(|v| v.starts_with(c)))
            })
            .unwrap_or_else(|| {
                panic!(
                    "{}: no daemon {name} span under cmd {}: {daemon_spans:#?}",
                    r.verb, cmd.span_id
                )
            });
        if r.verb == "exec" {
            exec_span_id = request.field("span_id").map(str::to_owned);
        }
    }

    // A nested `min`, handed what the box would get, continues the trace
    // under the exec's daemon span.
    let exec_span_id = exec_span_id.unwrap();
    let handed = format!("00-{TRACE}-{exec_span_id}-01");
    let nested_spool = private_tempdir();
    let (out, _) = run_min_env(
        &args,
        &[
            ("MINIMAL_TELEMETRY", "1"),
            (
                "MINIMAL_OTEL_SPOOL_DIR",
                nested_spool.path().to_str().unwrap(),
            ),
            ("TRACEPARENT", handed.as_str()),
        ],
        &["ls"],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nested = spooled_spans(nested_spool.path());
    let nested_cmd = nested.iter().find(|s| s.name == "cmd").unwrap();
    assert_eq!(nested_cmd.trace_id, TRACE, "{nested_cmd:?}");
    assert_eq!(
        nested_cmd.parent_span_id, exec_span_id,
        "the nested min is the exec span's child"
    );

    // Telemetry off: nothing crosses.
    const INHERITED: &str = "0af7651916cd43dd8448eb211c80319e";
    let off_col = collector();
    let inherited = format!("00-{INHERITED}-{PARENT}-01");
    let off = [
        ("DO_NOT_TRACK", "1"),
        ("MINIMAL_TELEMETRY", "1"),
        ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", off_col.url.as_str()),
        ("TRACEPARENT", inherited.as_str()),
    ];
    let marked_before = log.find("exec", "telemetry", "opt-out").len()
        + log.find("attach", "telemetry", "opt-out").len();
    for r in run_the_verbs(&daemon, &args, &off).await {
        assert!(r.cmd.is_none(), "{}: spooled with telemetry off", r.verb);
    }
    assert!(off_col.requests.lock().unwrap().is_empty(), "nothing sent");
    assert!(
        in_trace(&log, INHERITED).is_empty(),
        "no daemon span joined the inherited trace"
    );
    let marked = log.find("exec", "telemetry", "opt-out").len()
        + log.find("attach", "telemetry", "opt-out").len();
    assert_eq!(
        marked - marked_before,
        4,
        "each verb's daemon span is marked opted out"
    );
}
