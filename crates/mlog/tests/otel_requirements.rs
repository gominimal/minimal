//! Proofs of the telemetry requirements (spec 25, `TEL-*`; the lab's older
//! `OT-*`/`BE-*`/`SP-*`/`TR-*`/`VM-*`/`PV-*` ids map onto them, see
//! [`FORMER_IDS`]) through `mlog::otel`'s public API, the way a binary uses
//! it: `init`, the layers in a subscriber, `align`, `relocate_spool`, the
//! exit flush.
//!
//! `init` is once per process, so each case runs one helper of this binary
//! in a child process whose environment starts with every `OTEL_*`,
//! `MINIMAL_*` and `DO_NOT_TRACK` variable removed. A helper is a test that
//! does nothing unless `MLOG_REQ_CHILD` is set (not `#[ignore]`: `just
//! test-ignored` runs every ignored test, and a helper calls
//! `process::exit`). It reports through `MARK <key> <value>` lines on
//! stdout; the parent reads those and the spool the child wrote.
//!
//! A requirement the stack does not meet yet (an open review item), or that
//! only the lab exercises, is a test that returns early unless
//! `TEST_KNOWN_GAPS=1`: it fails today, naming the gap and the issue that
//! tracks it ([`KNOWN_GAPS`]), and its fix drops the guard.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value as J;
use tracing_subscriber::prelude::*;

/// The tests' and helpers' shared code: in a `cfg(test)` module, so the
/// test-code allowances (`unwrap`, `panic`, indexing) apply to it as well.
#[cfg(test)]
mod support {
    use super::*;

    // ---- the parent's side ----

    /// Run the helper test `helper` in a child with a stripped telemetry
    /// environment plus `env`; panics unless it succeeds. Returns its stdout.
    pub(super) fn child(helper: &str, env: &[(&str, &str)]) -> String {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", helper, "--nocapture", "--test-threads=1"]);
        for (k, _) in std::env::vars_os() {
            let name = k.to_string_lossy();
            if name.starts_with("OTEL_") || name.starts_with("MINIMAL_") || name == "DO_NOT_TRACK" {
                c.env_remove(&k);
            }
        }
        c.env_remove("RUST_LOG");
        c.env("MLOG_REQ_CHILD", "1");
        c.envs(env.iter().copied());
        let out = c.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "{helper} failed\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout
    }

    /// The value of every `MARK <key> <value>` line (libtest may print
    /// `test <name> ... ` on the same line first).
    pub(super) fn marks(out: &str, key: &str) -> Vec<String> {
        let tag = format!("MARK {key} ");
        out.lines()
            .filter_map(|l| Some(l.split_once(&tag)?.1.trim().to_owned()))
            .collect()
    }

    pub(super) fn mark(out: &str, key: &str) -> String {
        marks(out, key)
            .pop()
            .unwrap_or_else(|| panic!("no MARK {key} in {out}"))
    }

    /// Every `*.jsonl` file in `dir`, sorted.
    pub(super) fn spool_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.map(|e| e.unwrap().path())
                    .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    /// Every spool line in `dir`, parsed; panics on a line that is not JSON.
    pub(super) fn spool(dir: &Path) -> Vec<J> {
        spool_files(dir)
            .iter()
            .flat_map(|p| {
                std::fs::read_to_string(p)
                    .unwrap()
                    .lines()
                    .map(|l| {
                        serde_json::from_str(l)
                            .unwrap_or_else(|e| panic!("spool line is not JSON ({e}): {l}"))
                    })
                    .collect::<Vec<J>>()
            })
            .collect()
    }

    /// Every span in `lines`, with its resource.
    pub(super) fn spans(lines: &[J]) -> Vec<(&J, &J)> {
        let mut v = Vec::new();
        for l in lines {
            for rs in l["resourceSpans"].as_array().into_iter().flatten() {
                for ss in rs["scopeSpans"].as_array().into_iter().flatten() {
                    for s in ss["spans"].as_array().into_iter().flatten() {
                        v.push((&rs["resource"], s));
                    }
                }
            }
        }
        v
    }

    /// Every log record in `lines`: its resource, its scope name (the event's
    /// target) and the record.
    pub(super) fn logs(lines: &[J]) -> Vec<(&J, String, &J)> {
        let mut v = Vec::new();
        for l in lines {
            for rl in l["resourceLogs"].as_array().into_iter().flatten() {
                for sl in rl["scopeLogs"].as_array().into_iter().flatten() {
                    let scope = sl["scope"]["name"].as_str().unwrap_or_default().to_owned();
                    for r in sl["logRecords"].as_array().into_iter().flatten() {
                        v.push((&rl["resource"], scope.clone(), r));
                    }
                }
            }
        }
        v
    }

    pub(super) fn span_names(lines: &[J]) -> Vec<String> {
        spans(lines)
            .iter()
            .map(|(_, s)| s["name"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    pub(super) fn log_bodies(lines: &[J]) -> Vec<String> {
        logs(lines)
            .iter()
            .map(|(_, _, r)| {
                r["body"]["stringValue"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    /// A resource attribute's string value, if the resource has it.
    pub(super) fn resource_attr(resource: &J, key: &str) -> Option<String> {
        resource["attributes"]
            .as_array()?
            .iter()
            .find(|a| a["key"] == key)?["value"]["stringValue"]
            .as_str()
            .map(str::to_owned)
    }

    pub(super) fn to_str(p: &Path) -> &str {
        p.to_str().unwrap()
    }

    /// A minimal OTLP/HTTP collector on 127.0.0.1: answers every request with
    /// an empty 200 and keeps each request's header block (lowercased).
    pub(super) struct Collector {
        pub(super) url: String,
        pub(super) requests: Arc<Mutex<Vec<String>>>,
    }

    pub(super) fn collector() -> Collector {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let requests: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = requests.clone();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(conn) = conn else { continue };
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut w = conn.try_clone().unwrap();
                    let mut r = std::io::BufReader::new(conn);
                    loop {
                        let mut head = String::new();
                        let mut line = String::new();
                        while r.read_line(&mut line).is_ok_and(|n| n > 0) {
                            if line == "\r\n" {
                                break;
                            }
                            head.push_str(&line.to_ascii_lowercase());
                            line.clear();
                        }
                        if head.is_empty() {
                            return;
                        }
                        let len: usize = head
                            .lines()
                            .find_map(|h| h.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        let mut body = vec![0; len];
                        if r.read_exact(&mut body).is_err() {
                            return;
                        }
                        seen.lock().unwrap().push(head);
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

    // ---- the children's side (helpers, run only by the tests above) ----

    /// Whether this process is a helper's child (see the module docs).
    pub(super) fn in_child() -> bool {
        std::env::var_os("MLOG_REQ_CHILD").is_some()
    }

    /// A layer that records the target of every event and span it sees, and
    /// prints each new one as `MARK census <target>` when `print`.
    pub(super) struct Census {
        pub(super) seen: Arc<Mutex<Vec<String>>>,
        pub(super) print: bool,
    }

    impl Census {
        fn note(&self, target: &str) {
            let mut seen = self.seen.lock().unwrap();
            if self.print && !seen.iter().any(|t| t == target) {
                println!("MARK census {target}");
            }
            seen.push(target.to_owned());
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Census {
        fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            self.note(e.metadata().target());
        }

        fn on_new_span(
            &self,
            a: &tracing::span::Attributes<'_>,
            _: &tracing::span::Id,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.note(a.metadata().target());
        }
    }

    /// `init` plus the export layers, as `min` and the daemons assemble them.
    /// A layer that prints the message of every WARN event as
    /// `MARK warn <message>`.
    pub(super) struct Warnings;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    if f.name() == "message" {
                        self.0 = format!("{v:?}");
                    }
                }
            }
            if *e.metadata().level() == tracing::Level::WARN {
                let mut m = Message(String::new());
                e.record(&mut m);
                println!("MARK warn {}", m.0);
            }
        }
    }

    pub(super) fn installed() -> impl tracing::Subscriber + Send + Sync {
        mlog::otel::init("minimald");
        tracing_subscriber::registry()
            .with(mlog::otel::span_layer())
            .with(mlog::otel::log_layer())
    }

    // ---- more helpers ----

    /// Every `*.jsonl` under `dir`, recursively.
    pub(super) fn jsonl_under(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let p = e.unwrap().path();
            if p.is_dir() {
                jsonl_under(&p, out);
            } else if p.extension().is_some_and(|x| x == "jsonl") {
                out.push(p);
            }
        }
    }

    /// A temporary directory with mode 0700: the spool refuses a directory
    /// with group or other bits, and `tempfile` creates its directories with
    /// the umask's default (0755).
    pub(super) fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    /// The guard every known-gap test starts with: the gap `id` is looked
    /// up in [`super::KNOWN_GAPS`] (a missing id panics, so a test never
    /// names a gap the list no longer holds, and a reordered list cannot
    /// move a test onto another gap); then nothing unless
    /// `TEST_KNOWN_GAPS=1`, then a failure that names the gap.
    pub(super) fn known_gap(id: &str) {
        let gap = super::KNOWN_GAPS
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("{id} is not in KNOWN_GAPS"));
        if std::env::var_os("TEST_KNOWN_GAPS").is_none_or(|v| v.is_empty() || v == "0") {
            return;
        }
        panic!(
            "{}: no test in the repository; covered by {}; tracked as {}",
            gap.id, gap.covered_by, gap.issue
        );
    }

    /// Every `.rs` file under `dir`, recursively (none if it does not exist).
    pub(super) fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Every `<prefix><id>` token in `line`: the prefix followed by digits, or
    /// by `N` and digits (`TEL-N01`), ended by a non-id byte.
    pub(super) fn ids_in(line: &str, prefix: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = line;
        while let Some(at) = rest.find(prefix) {
            let before_ok = at == 0
                || !rest
                    .as_bytes()
                    .get(at - 1)
                    .is_some_and(|b| b.is_ascii_alphanumeric());
            let tail = rest.get(at + prefix.len()..).unwrap_or_default();
            let n = tail
                .bytes()
                .take_while(|b| b.is_ascii_digit() || *b == b'N')
                .count();
            let id = tail.get(..n).unwrap_or_default();
            let well_formed = n > 0
                && id.bytes().filter(|b| *b == b'N').count() <= 1
                && !id.ends_with('N')
                && !tail
                    .as_bytes()
                    .get(n)
                    .is_some_and(|b| b.is_ascii_alphanumeric());
            if before_ok && well_formed {
                out.push(format!("{prefix}{id}"));
            }
            rest = tail;
        }
        out
    }
}

use support::*;

// ---- the requirements ----

/// TEL-018, TEL-020: an explicit
/// `MINIMAL_OTEL_SPOOL_DIR` survives `relocate_spool`, the call minimald
/// makes once it knows its state directory, so a spool the caller placed
/// (the scenario's small tmpfs) stays where it was put.
#[test]
fn an_explicit_spool_dir_survives_relocation() {
    let tmp = private_tempdir();
    let (pinned, state) = (tmp.path().join("pinned"), tmp.path().join("state"));
    child(
        "helper_record",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(&pinned)),
            ("MLOG_REQ_RELOCATE", to_str(&state)),
        ],
    );
    assert!(
        span_names(&spool(&pinned)).contains(&"req-span".to_owned()),
        "the span is in the pinned directory"
    );
    assert!(
        !state.exists(),
        "nothing was written to the state directory"
    );
}

/// TEL-006: the resource carries a `service.instance.id`
/// of 32 hex digits, one per process (two processes differ, every record of
/// one signal in a process agrees), never the machine id, and there is no
/// `host.id`.
#[test]
fn one_instance_id_per_process_and_never_the_machine_id() {
    let machine_ids: Vec<String> = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let mut per_process = Vec::new();
    for _ in 0..2 {
        let tmp = private_tempdir();
        child(
            "helper_record",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ],
        );
        let lines = spool(tmp.path());
        let resources: Vec<&J> = spans(&lines)
            .into_iter()
            .map(|(r, _)| r)
            .chain(logs(&lines).into_iter().map(|(r, _, _)| r))
            .collect();
        assert!(resources.len() >= 2, "a span and a log were spooled");
        let mut ids = Vec::new();
        for r in &resources {
            let id = resource_attr(r, "service.instance.id")
                .unwrap_or_else(|| panic!("no service.instance.id in {r}"));
            assert!(
                id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                "not 32 hex digits: {id}"
            );
            assert!(!machine_ids.contains(&id), "the machine id was exported");
            assert!(resource_attr(r, "host.id").is_none(), "host.id in {r}");
            ids.push(id);
        }
        let span_id = resource_attr(spans(&lines)[0].0, "service.instance.id");
        assert!(
            spans(&lines)
                .iter()
                .all(|(r, _)| resource_attr(r, "service.instance.id") == span_id),
            "one id across a process's spans"
        );
        per_process.push(ids);
    }
    assert!(
        per_process[0].iter().all(|a| !per_process[1].contains(a)),
        "two processes share an instance id: {per_process:?}"
    );
}

/// TEL-006: the traces and the logs of one process carry the same
/// `service.instance.id`, so a backend can join them.
#[test]
fn the_trace_and_log_resources_of_a_process_share_one_instance_id() {
    let tmp = private_tempdir();
    child(
        "helper_record",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
        ],
    );
    let lines = spool(tmp.path());
    let span_id = resource_attr(spans(&lines)[0].0, "service.instance.id");
    let log_id = resource_attr(logs(&lines)[0].0, "service.instance.id");
    assert!(span_id.is_some());
    assert_eq!(span_id, log_id, "traces and logs name different instances");
}

/// The exporter's own stack, as targets (the crate's `NEVER_EXPORT`).
const STACK: &[&str] = &[
    "hyper",
    "hyper_util::client::legacy",
    "h2",
    "reqwest::connect",
    "tower",
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "opentelemetry_http",
];

/// TEL-013: with the export filter opened all the way (`MINIMAL_OTEL_FILTER=
/// trace`), no span or event from the exporter's HTTP stack or the SDK
/// reaches the spool, at any level, while minimal's own targets do.
#[test]
fn the_export_filter_never_admits_the_exporters_own_stack() {
    let tmp = private_tempdir();
    child(
        "helper_stack_targets",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ("MINIMAL_OTEL_FILTER", "trace"),
        ],
    );
    let lines = spool(tmp.path());
    let names = span_names(&lines);
    let scopes: Vec<String> = logs(&lines).into_iter().map(|(_, s, _)| s).collect();
    assert!(names.contains(&"own-span".to_owned()), "control: {names:?}");
    assert!(
        scopes.contains(&"minimald".to_owned()),
        "control: {scopes:?}"
    );
    for t in STACK {
        assert!(
            !names.contains(&format!("stack-span {t}")),
            "a {t} span was exported"
        );
        assert!(!scopes.iter().any(|s| s == t), "a {t} event was exported");
    }
}

/// TEL-013: a user directive more specific than the never-export one
/// (`hyper_util::client=trace` beside `hyper_util=off`) must not let the
/// exporter's stack back in: an `EnvFilter` lets the more specific
/// directive win (tracing-subscriber 0.3), so the exclusion is
/// a filter of its own after the user's.
#[test]
fn a_specific_directive_cannot_readmit_the_exporters_stack() {
    let tmp = private_tempdir();
    child(
        "helper_stack_targets",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            (
                "MINIMAL_OTEL_FILTER",
                "trace,hyper_util::client=trace,opentelemetry_sdk::trace=trace",
            ),
        ],
    );
    let lines = spool(tmp.path());
    let scopes: Vec<String> = logs(&lines).into_iter().map(|(_, s, _)| s).collect();
    assert!(
        scopes.contains(&"minimald".to_owned()),
        "control: {scopes:?}"
    );
    for t in STACK {
        assert!(!scopes.iter().any(|s| s == t), "a {t} event was exported");
    }
}

/// TEL-013, end to end: export to a collector that answers, with the filter at
/// `trace` and a census layer beside the export layers. Whatever the HTTP
/// stack and the SDK emit while exporting (the census sees it), none of it
/// is spooled. With today's dependency features the stack emits no tracing
/// events at all (the census sees only this test's own), so this guards a
/// feature flip; the filter itself is proved by
/// [`the_export_filter_never_admits_the_exporters_own_stack`].
#[test]
fn a_real_export_spools_nothing_from_its_own_stack() {
    let tmp = private_tempdir();
    let col = collector();
    let out = child(
        "helper_census",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ("MINIMAL_OTEL_FILTER", "trace"),
            ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", &col.url),
        ],
    );
    assert!(
        !col.requests.lock().unwrap().is_empty(),
        "control: the collector got no export"
    );
    let lines = spool(tmp.path());
    assert!(span_names(&lines).contains(&"req-span".to_owned()));
    let exported: Vec<String> = logs(&lines).into_iter().map(|(_, s, _)| s).collect();
    for target in marks(&out, "census") {
        let stack = STACK
            .iter()
            .any(|t| target.split("::").next() == t.split("::").next());
        if stack {
            assert!(
                !exported.contains(&target),
                "{target} emitted during export and was spooled"
            );
        }
    }
    for s in &exported {
        let root = s.split("::").next().unwrap_or_default();
        assert!(
            !STACK.iter().any(|t| t.split("::").next() == Some(root)),
            "{s} was spooled"
        );
    }
}

/// TEL-019 (and the code-review refusal): a spool directory the spool
/// creates (and any parent it creates)
/// is 0700, and its files are 0600. A directory that already exists keeps
/// its mode (the spool does not chmod what it did not create); the file in
/// it is still 0600.
#[cfg(unix)]
#[test]
fn spool_files_are_0600_in_a_0700_directory() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let tmp = private_tempdir();
    let fresh = tmp.path().join("made").join("spool");
    child(
        "helper_record",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(&fresh)),
        ],
    );
    assert_eq!(mode(&fresh), 0o700, "the spool directory");
    assert_eq!(mode(&tmp.path().join("made")), 0o700, "a created parent");
    let files = spool_files(&fresh);
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(mode(&files[0]), 0o600, "the spool file");

    // A directory that already exists keeps its mode. One that grants
    // group or other access is refused: nothing is spooled
    // there, and the process spools to the state-dir default instead.
    let existing = tmp.path().join("existing");
    std::fs::DirBuilder::new()
        .mode(0o750)
        .create(&existing)
        .unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o750)).unwrap();
    let state_home = tmp.path().join("state");
    child(
        "helper_record",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(&existing)),
            ("XDG_STATE_HOME", to_str(&state_home)),
        ],
    );
    assert_eq!(mode(&existing), 0o750, "a directory it did not create");
    assert_eq!(spool_files(&existing), Vec::<PathBuf>::new(), "refused");
    let mut fallback = Vec::new();
    jsonl_under(&state_home, &mut fallback);
    assert_eq!(
        fallback.len(),
        1,
        "one file in the state-dir spool: {fallback:?}"
    );
    let spool = fallback[0].parent().unwrap();
    assert!(spool.ends_with("telemetry/spool"), "{}", spool.display());
    assert_eq!(mode(spool), 0o700, "the fallback spool directory");
    assert_eq!(mode(&fallback[0]), 0o600, "its spool file");
}

/// TEL-018: when the spool's file
/// cannot grow (the filesystem is full; here `RLIMIT_FSIZE` at the file's
/// size), records are dropped, the spool stays on, and the first record
/// after space returns is written, whole, to the same file, without a
/// restart. Every line in the file is a whole record.
#[cfg(target_os = "linux")]
#[test]
fn a_full_spool_drops_records_then_resumes_when_space_returns() {
    let tmp = private_tempdir();
    child(
        "helper_full_disk",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
        ],
    );
    assert_eq!(spool_files(tmp.path()).len(), 1, "one file, no rotation");
    let names = span_names(&spool(tmp.path()));
    assert_eq!(names, ["before-full", "after-full"], "{names:?}");
}

/// TEL-024: a span the export filter rejects is not
/// aligned (no ids to propagate, so a box gets no `TRACEPARENT` pointing at
/// a span nobody records); one the filter admits adopts the propagated
/// parent and is spooled under its trace.
#[test]
fn a_span_the_export_filter_rejects_is_not_aligned() {
    let tmp = private_tempdir();
    let out = child(
        "helper_align",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ("MINIMAL_OTEL_FILTER", "warn"),
            ("MLOG_REQ_FLAGS", "1"),
        ],
    );
    assert_eq!(mark(&out, "exec"), "None", "a rejected span is not aligned");
    assert_eq!(
        mark(&out, "kept"),
        format!("{} 1", "11".repeat(16)),
        "an admitted span joins the propagated trace"
    );
    let lines = spool(tmp.path());
    let spans = spans(&lines);
    assert!(!span_names(&lines).contains(&"exec".to_owned()));
    let kept = spans
        .iter()
        .find(|(_, s)| s["name"] == "kept")
        .map(|(_, s)| *s)
        .unwrap_or_else(|| panic!("kept is not spooled: {lines:?}"));
    assert_eq!(kept["traceId"], "11".repeat(16));
    assert_eq!(kept["parentSpanId"], "22".repeat(8));
}

/// TEL-024: under an unsampled propagated parent (flags 00)
/// the span keeps the trace id and the flags 00 it would propagate, nothing
/// of it is spooled, and its events still are.
#[test]
fn an_unsampled_parent_propagates_flags_00_and_spools_nothing() {
    let tmp = private_tempdir();
    let out = child(
        "helper_align",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ("MLOG_REQ_FLAGS", "0"),
        ],
    );
    assert_eq!(
        mark(&out, "exec"),
        format!("{} 0", "11".repeat(16)),
        "same trace, flags 00"
    );
    let lines = spool(tmp.path());
    assert!(span_names(&lines).is_empty(), "{lines:?}");
    assert!(
        log_bodies(&lines).contains(&"inside-exec".to_owned()),
        "logs still spool: {lines:?}"
    );
}

/// TEL-005: with traces off (`OTEL_TRACES_EXPORTER=none`) and
/// logs on, no tracer is installed: no span layer, `exporting()` is false,
/// `align` gives nothing to propagate, and events still spool as logs.
#[test]
fn logs_only_installs_no_tracer() {
    let tmp = private_tempdir();
    let out = child(
        "helper_logs_only",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ("OTEL_TRACES_EXPORTER", "none"),
        ],
    );
    assert_eq!(mark(&out, "layers"), "span=false log=true exporting=false");
    assert_eq!(mark(&out, "align"), "None");
    let lines = spool(tmp.path());
    assert!(span_names(&lines).is_empty(), "{lines:?}");
    assert!(log_bodies(&lines).contains(&"logs-only-event".to_owned()));
}

/// TEL-010: a CLI that leaves through
/// `process::exit` flushes from the atexit hook within its bound, against a
/// collector that accepts and never answers, and the span is spooled.
#[test]
fn the_atexit_flush_is_bounded_on_process_exit() {
    let tarpit = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", tarpit.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for c in tarpit.incoming() {
            held.push(c); // accepted, never read, never answered
        }
    });
    let tmp = private_tempdir();
    let out = child(
        "helper_exit",
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", &url),
        ],
    );
    let exited = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let before: u128 = mark(&out, "exit_at").parse().unwrap();
    let took = exited.saturating_sub(before);
    // TEL-010's bound, `CLI_EXIT_FLUSH` plus 250 ms of shutdown slack, and
    // a margin for what this measures besides the flush: the child's
    // teardown after the hook and this process reading its output. 100 ms
    // covers that on a loaded test runner; a regression in the flush
    // itself overruns it.
    const SHUTDOWN_SLACK_MS: u128 = 250;
    const MEASUREMENT_MARGIN_MS: u128 = 100;
    let bound = mlog::otel::CLI_EXIT_FLUSH.as_millis() + SHUTDOWN_SLACK_MS + MEASUREMENT_MARGIN_MS;
    assert!(
        took < bound,
        "process::exit took {took} ms against a silent collector (bound {bound} ms)"
    );
    assert!(span_names(&spool(tmp.path())).contains(&"exit-span".to_owned()));
}

/// TEL-008: with a `MINIMAL_`-prefixed endpoint, the ambient
/// `OTEL_EXPORTER_OTLP_HEADERS` (a developer's key for another backend) is
/// never sent to it. Without `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` the export
/// is refused with one warning per signal and the spool is written as
/// usual; with it, its headers are sent and the plain ones are not. A plain
/// endpoint still gets the plain headers.
#[test]
fn a_prefixed_endpoint_never_carries_plain_headers() {
    let ambient = [
        ("MINIMAL_TELEMETRY", "1"),
        ("OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=S3CRET,x-plain=1"),
        (
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
            "x-api-key=S3CRET,x-traces=1",
        ),
    ];

    // Refused: nothing reaches the collector, the spool has the span.
    let col = collector();
    let tmp = private_tempdir();
    let mut env = ambient.to_vec();
    env.push(("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", &col.url));
    env.push(("MINIMAL_OTEL_SPOOL_DIR", to_str(tmp.path())));
    let out = child("helper_export", &env);
    assert_eq!(
        marks(&out, "warn"),
        [
            "telemetry: refusing to export traces: OTEL_EXPORTER_OTLP_TRACES_HEADERS is set but \
             the endpoint comes from MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT; set \
             MINIMAL_OTEL_EXPORTER_OTLP_HEADERS to send headers there",
            "telemetry: refusing to export logs: OTEL_EXPORTER_OTLP_HEADERS is set but the \
             endpoint comes from MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT; set \
             MINIMAL_OTEL_EXPORTER_OTLP_HEADERS to send headers there",
        ]
    );
    assert!(
        col.requests.lock().unwrap().is_empty(),
        "a refused export reached the collector"
    );
    assert!(span_names(&spool(tmp.path())).contains(&"req-span".to_owned()));

    // MINIMAL_ headers: sent, and only they.
    let col = collector();
    let mut env = ambient.to_vec();
    env.push(("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", &col.url));
    env.push(("MINIMAL_OTEL_SPOOL", "0"));
    env.push((
        "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS",
        "x-api-key=ours,x-minimal=1",
    ));
    let out = child("helper_export", &env);
    assert!(marks(&out, "warn").is_empty(), "{out}");
    let requests = col.requests.lock().unwrap();
    assert!(!requests.is_empty(), "control: the collector got no export");
    for r in requests.iter() {
        assert!(!r.contains("s3cret"), "an ambient header was sent: {r}");
        assert!(!r.contains("x-plain") && !r.contains("x-traces"), "{r}");
        assert!(
            r.contains("x-api-key: ours") && r.contains("x-minimal: 1"),
            "{r}"
        );
    }
    drop(requests);

    // A plain endpoint: the plain headers, as for any OTel program.
    let col = collector();
    let mut env = ambient.to_vec();
    env.push(("OTEL_EXPORTER_OTLP_ENDPOINT", &col.url));
    env.push(("MINIMAL_OTEL_SPOOL", "0"));
    child("helper_export", &env);
    let requests = col.requests.lock().unwrap();
    assert!(!requests.is_empty(), "control: the collector got no export");
    assert!(
        requests.iter().all(|r| r.contains("x-api-key: s3cret")),
        "{requests:?}"
    );
}

/// TEL-012: `quiet` silences the SDK's own events on a console
/// filter (a down collector prints no ERROR lines) and keeps everything the
/// caller's directives show.
#[test]
fn quiet_drops_sdk_errors_and_keeps_the_rest() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let filter = mlog::otel::quiet(tracing_subscriber::EnvFilter::new("info,minimald=debug"));
    let subscriber = tracing_subscriber::registry().with(
        Census {
            seen: seen.clone(),
            print: false,
        }
        .with_filter(filter),
    );
    tracing::subscriber::with_default(subscriber, || {
        tracing::error!(target: "opentelemetry", "x");
        tracing::error!(target: "opentelemetry_sdk", "x");
        tracing::error!(target: "opentelemetry_otlp", "x");
        tracing::error!(target: "opentelemetry_http", "x");
        tracing::debug!(target: "minimald", "x");
        tracing::info!(target: "minimal", "x");
        tracing::debug!(target: "minimal", "x");
    });
    assert_eq!(*seen.lock().unwrap(), ["minimald", "minimal"]);
}

/// A requirement with no test in this repository: what covers it today and
/// the issue that tracks closing the gap.
struct KnownGap {
    id: &'static str,
    covered_by: &'static str,
    issue: &'static str,
}

/// Every known gap, one test each below. These tests run no product code:
/// each names one gap, what covers it today and the issue that tracks it,
/// and fails on request (`TEST_KNOWN_GAPS=1`) so a lane can list the gaps.
/// An entry leaves when the requirement gets a real test; nothing here
/// notices that by itself, so the change that adds the test removes the
/// entry. The list matches the spec's known-gaps paragraph.
const KNOWN_GAPS: &[KnownGap] = &[
    KnownGap {
        id: "TEL-009",
        covered_by: "lab scenario 785 only (a daemon keeps its own switches across a client's)",
        issue: "minimal#2033",
    },
    KnownGap {
        id: "TEL-034",
        covered_by: "the VM tests \
                     `the_guest_daemons_records_reach_the_host_spool_and_endpoint_over_vsock` and \
                     `a_boot_and_stop_share_one_trace_with_the_guest_daemon`, gated \
                     `MINVMD_E2E=1`, so they run on the VM lane only; lab scenarios 715b, \
                     715f and 715i to 715l",
        issue: "minimal#2034",
    },
    KnownGap {
        id: "TEL-044",
        covered_by: "each collector's scrub by unit tests \
                     (`a_host_bundle_never_carries_a_header_value_or_a_secret_attribute`, \
                     `a_daemon_bundle_never_carries_a_header_value_or_a_secret_attribute`), \
                     the host's whole `min bug` collection by \
                     `a_bundle_collected_with_telemetry_on_carries_no_secret`; \
                     the whole path, a nested bundle from a real VM, by lab scenario 782 only",
        issue: "minimal#2035",
    },
    KnownGap {
        id: "TEL-047",
        covered_by: "nothing: nothing in the tree reports a box's injected environment, and \
                     `min box spec` is spec 24's future work",
        issue: "minimal#2036",
    },
    KnownGap {
        id: "TEL-032 on macOS",
        covered_by: "unit coverage only (`a_task_that_outlives_ready_does_not_hold_the_start_phase_open`); \
                     the ready()-phase flush was found missing on macOS 2026-10-05 and no macOS \
                     lane runs the supervisor",
        issue: "minimal#2037",
    },
];

#[test]
fn known_gap_tel_009_a_daemon_keeps_its_own_switches() {
    known_gap("TEL-009");
}

#[test]
fn known_gap_tel_034_the_guest_path_runs_on_the_vm_lane_only() {
    known_gap("TEL-034");
}

#[test]
fn known_gap_tel_044_the_bug_bundle_carries_the_spools() {
    known_gap("TEL-044");
}

#[test]
fn known_gap_tel_047_the_box_spec_shows_traceparent() {
    known_gap("TEL-047");
}

#[test]
fn known_gap_tel_032_on_macos_the_ready_phase_flushes() {
    known_gap("TEL-032 on macOS");
}

/// Every known gap names a spec id, what covers it today and an issue to
/// close it under; a placeholder issue is spelled `minimal#TBD-<slug>`
/// until it is filed.
#[test]
fn known_gaps_name_a_spec_id_a_coverage_and_an_issue() {
    for gap in KNOWN_GAPS {
        assert!(
            gap.id.starts_with("TEL-") && gap.id.len() >= 7,
            "{}: not a spec id",
            gap.id
        );
        assert!(
            !gap.covered_by.trim().is_empty(),
            "{}: what covers it?",
            gap.id
        );
        assert!(
            gap.issue.starts_with("minimal#") && gap.issue.len() > "minimal#".len(),
            "{}: issue {} is neither minimal#<n> nor minimal#TBD-<slug>",
            gap.id,
            gap.issue
        );
        if let Some(slug) = gap.issue.strip_prefix("minimal#TBD-") {
            assert!(
                !slug.is_empty()
                    && slug
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{}: placeholder slug {slug:?} is not kebab-case",
                gap.id
            );
        }
    }
}

/// Gaps are found by id: each id is listed once, and each
/// listed gap has the test that names it, so a gap cannot sit in the list
/// with no test failing for it under `TEST_KNOWN_GAPS=1`.
#[test]
fn every_known_gap_is_listed_once_and_has_its_test() {
    let src = include_str!("otel_requirements.rs");
    for (i, gap) in KNOWN_GAPS.iter().enumerate() {
        assert!(
            KNOWN_GAPS.iter().skip(i + 1).all(|g| g.id != gap.id),
            "{} is listed twice",
            gap.id
        );
        assert!(
            src.contains(&format!("    known_gap(\"{}\");", gap.id)),
            "{} has no known_gap test",
            gap.id
        );
    }
}

/// The requirement ids the lab's notes, scenario headers and proof tables
/// used before 2026-10-05, and the spec 25 id each became
/// (`patches/lab-scenarios-spec-ids-20261005/idmap.json`, the rename's
/// own map). One to one.
const FORMER_IDS: &[(&str, &str)] = &[
    ("OT-1", "TEL-001"),
    ("OT-2", "TEL-002"),
    ("OT-3", "TEL-003"),
    ("OT-4", "TEL-004"),
    ("OT-5", "TEL-005"),
    ("OT-6", "TEL-006"),
    ("OT-7", "TEL-007"),
    ("OT-8", "TEL-008"),
    ("OT-9", "TEL-009"),
    ("BE-1", "TEL-010"),
    ("BE-2", "TEL-011"),
    ("BE-3", "TEL-012"),
    ("BE-4", "TEL-013"),
    ("SP-1", "TEL-014"),
    ("SP-2", "TEL-015"),
    ("SP-3", "TEL-016"),
    ("SP-4", "TEL-017"),
    ("SP-5", "TEL-018"),
    ("SP-6", "TEL-019"),
    ("SP-7", "TEL-020"),
    ("TR-1", "TEL-021"),
    ("TR-2", "TEL-022"),
    ("TR-3", "TEL-023"),
    ("TR-4", "TEL-024"),
    ("TR-5", "TEL-025"),
    ("TR-6", "TEL-026"),
    ("TR-7", "TEL-027"),
    ("TR-8", "TEL-028"),
    ("TR-9", "TEL-029"),
    ("TR-10", "TEL-030"),
    ("TR-11", "TEL-031"),
    ("VM-1", "TEL-032"),
    ("VM-2", "TEL-033"),
    ("VM-3", "TEL-034"),
    ("VM-4", "TEL-035"),
    ("VM-5", "TEL-036"),
    ("VM-6", "TEL-037"),
    ("SD-1", "TEL-038"),
    ("SD-2", "TEL-039"),
    ("PV-1", "TEL-040"),
    ("PV-2", "TEL-041"),
    ("PV-3", "TEL-042"),
    ("PV-4", "TEL-043"),
    ("DG-1", "TEL-044"),
    ("BE-N01", "TEL-N01"),
    ("SP-N01", "TEL-N02"),
];

/// Spec 25 ids with no former id (the spec's table
/// maps them from `(none)`): a source that cites one cites a requirement
/// that exists, so they count as known below.
const NEW_IDS: &[&str] = &["TEL-045", "TEL-046", "TEL-047", "TEL-048", "TEL-051"];

/// The former ids map one to one onto spec 25's, and every `TEL-*` id a
/// test or a source comment in this workspace cites is one the map
/// produces, so a lab note in the old ids and a test in the new ones name
/// the same requirement; no former id survives in the sources.
#[test]
fn former_ids_map_one_to_one_onto_the_ids_the_tests_use() {
    use std::collections::BTreeSet;

    let former: BTreeSet<&str> = FORMER_IDS.iter().map(|(f, _)| *f).collect();
    let now: BTreeSet<&str> = FORMER_IDS.iter().map(|(_, n)| *n).collect();
    assert_eq!(former.len(), FORMER_IDS.len(), "a former id maps twice");
    assert_eq!(now.len(), FORMER_IDS.len(), "two former ids map to one");
    for (f, n) in FORMER_IDS {
        let (group, num) = f.split_once('-').unwrap_or_else(|| panic!("{f}: no group"));
        assert!(
            ["OT", "BE", "SP", "TR", "VM", "SD", "PV", "DG"].contains(&group),
            "{f}: unknown former group"
        );
        assert!(
            num.trim_start_matches('N')
                .bytes()
                .all(|b| b.is_ascii_digit()),
            "{f}: not a former id"
        );
        let tail = n
            .strip_prefix("TEL-")
            .unwrap_or_else(|| panic!("{n}: not a spec 25 id"));
        assert!(
            tail.len() == 3
                && tail
                    .trim_start_matches('N')
                    .bytes()
                    .all(|b| b.is_ascii_digit()),
            "{n}: not TEL-NNN or TEL-NNN with an N"
        );
    }

    // What the sources cite.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let krate = entry.unwrap().path();
        for sub in ["src", "tests"] {
            walk(&krate.join(sub), &mut files);
        }
    }
    assert!(
        files.len() > 50,
        "found only {} source files under {}",
        files.len(),
        crates.display()
    );
    let mut cited = BTreeSet::new();
    let mut stale = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap_or_default();
        for (i, line) in text.lines().enumerate() {
            for id in ids_in(line, "TEL-") {
                cited.insert(id);
            }
            for group in ["OT-", "BE-", "SP-", "TR-", "VM-", "SD-", "PV-", "DG-"] {
                for id in ids_in(line, group) {
                    // This file carries the map itself.
                    if f.ends_with("otel_requirements.rs") {
                        continue;
                    }
                    if former.contains(id.as_str()) {
                        stale.push(format!("{}:{}: {id}", f.display(), i + 1));
                    }
                }
            }
        }
    }
    assert!(
        stale.is_empty(),
        "former ids still in the sources:\n{}",
        stale.join("\n")
    );
    let known: BTreeSet<&str> = now.iter().copied().chain(NEW_IDS.iter().copied()).collect();
    let unknown: Vec<_> = cited
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "ids cited by the sources that no former id maps to: {unknown:?}"
    );
    let core: BTreeSet<&str> = FORMER_IDS
        .iter()
        .map(|(_, n)| *n)
        .filter(|n| !n.contains('N'))
        .collect();
    let uncited: Vec<_> = core.iter().filter(|id| !cited.contains(**id)).collect();
    assert!(
        uncited.len() < core.len() / 2,
        "most spec ids are cited by a test or a source comment; not these: {uncited:?}"
    );
}

/// One span with one event inside, after an optional `relocate_spool` to
/// `MLOG_REQ_RELOCATE`.
#[test]
fn helper_record() {
    if !in_child() {
        return;
    }
    let subscriber = installed();
    if let Some(d) = std::env::var_os("MLOG_REQ_RELOCATE") {
        mlog::otel::relocate_spool(d.into());
    }
    tracing::subscriber::with_default(subscriber, || {
        tracing::info_span!("req-span").in_scope(|| tracing::info!("req-event"));
    });
}

/// A span and an event at TRACE and at ERROR under each [`STACK`] target,
/// and one of each under `minimald` as the control.
#[test]
fn helper_stack_targets() {
    if !in_child() {
        return;
    }
    macro_rules! emit {
        ($($t:literal),*) => {$(
            drop(tracing::trace_span!(target: $t, concat!("stack-span ", $t)));
            drop(tracing::error_span!(target: $t, concat!("stack-span ", $t)));
            tracing::trace!(target: $t, "stack-event");
            tracing::error!(target: $t, "stack-event");
        )*};
    }
    tracing::subscriber::with_default(installed(), || {
        emit!(
            "hyper",
            "hyper_util::client::legacy",
            "h2",
            "reqwest::connect",
            "tower",
            "opentelemetry",
            "opentelemetry_sdk",
            "opentelemetry_otlp",
            "opentelemetry_http"
        );
        drop(tracing::trace_span!(target: "minimald", "own-span"));
        tracing::trace!(target: "minimald", "own-event");
    });
}

/// One span, exported through a real OTLP/HTTP client under a global
/// subscriber (the SDK's threads see it too) with a printing [`Census`].
#[test]
fn helper_census() {
    if !in_child() {
        return;
    }
    let census = Census {
        seen: Arc::default(),
        print: true,
    };
    tracing::subscriber::set_global_default(installed().with(census)).unwrap();
    tracing::info_span!("req-span").in_scope(|| tracing::info!("req-event"));
    mlog::otel::flush(Duration::from_secs(5));
    mlog::otel::shutdown(Duration::from_secs(5));
}

/// `report_init` (its warnings printed by [`Warnings`]), one span, then a
/// bounded shutdown (the export happens there).
#[test]
fn helper_export() {
    if !in_child() {
        return;
    }
    tracing::subscriber::with_default(installed().with(Warnings), || {
        mlog::otel::report_init();
        drop(tracing::info_span!("req-span"));
    });
    mlog::otel::shutdown(Duration::from_secs(5));
}

/// `before-full`; then the file is held at its size (`RLIMIT_FSIZE`, with
/// `SIGXFSZ` ignored so the write fails with `EFBIG` as on a full disk)
/// while three spans end; then the limit is lifted and `after-full` ends.
#[cfg(target_os = "linux")]
#[test]
fn helper_full_disk() {
    if !in_child() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os("MINIMAL_OTEL_SPOOL_DIR").unwrap());
    tracing::subscriber::with_default(installed(), || {
        drop(tracing::info_span!("before-full"));
        let files = spool_files(&dir);
        let len = std::fs::metadata(&files[0]).unwrap().len();
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: sets this process's own disposition of SIGXFSZ to ignore.
        unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        // SAFETY: a valid pointer to a local rlimit the call fills in.
        let got = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut old) };
        assert_eq!(got, 0, "getrlimit");
        let full = libc::rlimit {
            rlim_cur: len,
            rlim_max: old.rlim_max,
        };
        // SAFETY: a valid pointer to a local rlimit; lowers only the soft limit.
        let set = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &raw const full) };
        assert_eq!(set, 0, "setrlimit");
        for _ in 0..3 {
            drop(tracing::info_span!("while-full"));
        }
        assert_eq!(std::fs::metadata(&files[0]).unwrap().len(), len, "full");
        // SAFETY: a valid pointer to the limit read before, restored.
        let restored = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &raw const old) };
        assert_eq!(restored, 0, "setrlimit back");
        drop(tracing::info_span!("after-full"));
    });
}

/// `align` for an `info` span `exec` given the parent `11..`/`22..` with
/// flags `MLOG_REQ_FLAGS` (an event inside it), and for a `warn` span `kept`
/// given the same parent. Prints `MARK <name> <trace hex> <flags>` or
/// `MARK <name> None`.
#[test]
fn helper_align() {
    if !in_child() {
        return;
    }
    let flags: u8 = std::env::var("MLOG_REQ_FLAGS").unwrap().parse().unwrap();
    let parent = Some(([0x11; 16], [0x22; 8], flags));
    let show = |a: Option<([u8; 16], [u8; 8], u8)>| {
        a.map_or_else(
            || "None".to_owned(),
            |(t, _, f)| {
                let hex: String = t.iter().map(|b| format!("{b:02x}")).collect();
                format!("{hex} {f}")
            },
        )
    };
    tracing::subscriber::with_default(installed(), || {
        let exec = tracing::info_span!("exec");
        println!("MARK exec {}", show(mlog::otel::align(&exec, parent)));
        exec.in_scope(|| tracing::warn!("inside-exec"));
        drop(exec);
        let kept = tracing::warn_span!("kept");
        println!("MARK kept {}", show(mlog::otel::align(&kept, parent)));
        drop(kept);
    });
}

/// The layers `init` leaves with traces off, `align`'s answer, one event.
#[test]
fn helper_logs_only() {
    if !in_child() {
        return;
    }
    mlog::otel::init("minimald");
    let span_layer = mlog::otel::span_layer::<tracing_subscriber::Registry>();
    let log_layer = mlog::otel::log_layer::<tracing_subscriber::Registry>();
    println!(
        "MARK layers span={} log={} exporting={}",
        span_layer.is_some(),
        log_layer.is_some(),
        mlog::otel::exporting()
    );
    let subscriber = tracing_subscriber::registry().with(log_layer);
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("exec");
        let a = mlog::otel::align(&span, Some(([0x11; 16], [0x22; 8], 1)));
        println!("MARK align {}", if a.is_some() { "Some" } else { "None" });
        span.in_scope(|| tracing::info!("logs-only-event"));
    });
}

/// The CLI's exit path: one span, the CLI exit bound, then `process::exit`
/// (no explicit shutdown: the atexit hook flushes). Prints the time just
/// before the exit.
#[test]
fn helper_exit() {
    if !in_child() {
        return;
    }
    let subscriber = installed();
    mlog::otel::set_exit_flush(mlog::otel::CLI_EXIT_FLUSH);
    tracing::subscriber::with_default(subscriber, || {
        drop(tracing::info_span!("exit-span"));
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    println!("MARK exit_at {now}");
    std::process::exit(0);
}
