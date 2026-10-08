//! minvmd's OpenTelemetry through the real binary (spec 25: TEL-001,
//! TEL-009, TEL-032, TEL-036): the
//! trace context crosses the `min` → minvmd process boundary, the resource
//! names the service, and with telemetry off minvmd writes nothing.
//!
//! Like `config_cli_integration`, these run `minvmd status` against an
//! isolated state dir and need no VM. They read the local OTLP-JSON spool
//! (`MINIMAL_OTEL_SPOOL_DIR`), so no collector is involved either.

use std::path::Path;
use std::process::Command;

fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
const PARENT_ID: &str = "b7ad6b7169203331";

/// Run `minvmd status` with only the given telemetry variables set (every
/// ambient `OTEL_*` / `MINIMAL_*` / `DO_NOT_TRACK` / `RUST_LOG` removed
/// first).
fn status(state_home: &Path, spool: &Path, env: &[(&str, &str)]) {
    // A fresh state dir: stopped, exit 1 (the answer, not a failure).
    minvmd(&["status", "--json"], 1, state_home, spool, env);
}

/// Run `minvmd <args>` as [`status`] does and expect exit `code`.
fn minvmd(args: &[&str], code: i32, state_home: &Path, spool: &Path, env: &[(&str, &str)]) {
    let mut cmd = Command::new(minvmd_bin());
    cmd.args(args);
    for (k, _) in std::env::vars() {
        if k.starts_with("OTEL_")
            || k.starts_with("MINIMAL_")
            || k == "DO_NOT_TRACK"
            || k == "TRACEPARENT"
            || k == "RUST_LOG"
        {
            cmd.env_remove(k);
        }
    }
    cmd.env("XDG_STATE_HOME", state_home)
        .env("MINIMAL_OTEL_SPOOL_DIR", spool);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn minvmd");
    assert_eq!(
        out.status.code(),
        Some(code),
        "minvmd {args:?}: stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[expect(
    clippy::unwrap_used,
    reason = "a test helper: an unreadable or malformed spool must fail the test loudly"
)]
fn spool_lines(spool: &Path) -> Vec<serde_json_lenient::Value> {
    let Ok(rd) = std::fs::read_dir(spool) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            for l in std::fs::read_to_string(&p).unwrap().lines() {
                out.push(serde_json_lenient::from_str(l).unwrap());
            }
        }
    }
    out
}

#[expect(
    clippy::indexing_slicing,
    reason = "serde_json Value indexing returns Null for a missing key; it does not panic"
)]
fn spans(lines: &[serde_json_lenient::Value]) -> Vec<(String, serde_json_lenient::Value)> {
    let mut out = Vec::new();
    for l in lines {
        for rs in l["resourceSpans"].as_array().into_iter().flatten() {
            let service = rs["resource"]["attributes"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|a| a["key"] == "service.name")
                .and_then(|a| a["value"]["stringValue"].as_str())
                .unwrap_or_default()
                .to_string();
            for ss in rs["scopeSpans"].as_array().into_iter().flatten() {
                for s in ss["spans"].as_array().into_iter().flatten() {
                    out.push((service.clone(), s.clone()));
                }
            }
        }
    }
    out
}

#[test]
fn a_minvmd_root_span_is_a_child_of_the_callers_traceparent() {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("spool");
    let tp = format!("00-{TRACE_ID}-{PARENT_ID}-01");
    status(
        dir.path(),
        &spool,
        &[("MINIMAL_TELEMETRY", "1"), ("TRACEPARENT", &tp)],
    );
    let spans = spans(&spool_lines(&spool));
    let root = spans
        .iter()
        .find(|(_, s)| s["name"] == "minvmd")
        .unwrap_or_else(|| panic!("no minvmd root span in {spans:?}"));
    assert_eq!(root.0, "minvmd", "service.name");
    assert_eq!(root.1["traceId"], TRACE_ID);
    assert_eq!(root.1["parentSpanId"], PARENT_ID);
    // The subcommand is on the root span.
    let cmd = root.1["attributes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["key"] == "cmd")
        .and_then(|a| a["value"]["stringValue"].as_str());
    assert_eq!(cmd, Some("status"));
}

#[test]
fn without_a_traceparent_minvmd_starts_its_own_trace() {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("spool");
    status(dir.path(), &spool, &[("MINIMAL_TELEMETRY", "1")]);
    let spans = spans(&spool_lines(&spool));
    let root = spans
        .iter()
        .find(|(_, s)| s["name"] == "minvmd")
        .expect("root span");
    assert_ne!(root.1["traceId"], TRACE_ID);
    assert!(
        root.1["parentSpanId"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
}

#[test]
fn minvmd_writes_nothing_with_telemetry_off() {
    for env in [
        &[][..],
        &[("MINIMAL_TELEMETRY", "1"), ("DO_NOT_TRACK", "1")][..],
        &[("MINIMAL_TELEMETRY", "1"), ("OTEL_SDK_DISABLED", "true")][..],
        // An inbound context alone never turns anything on.
        &[(
            "TRACEPARENT",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )][..],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool");
        status(dir.path(), &spool, env);
        assert!(
            !spool.exists() || std::fs::read_dir(&spool).unwrap().next().is_none(),
            "spool written with {env:?}"
        );
    }
}

#[expect(
    clippy::indexing_slicing,
    reason = "serde_json Value indexing returns Null for a missing key; it does not panic"
)]
fn attr<'a>(span: &'a serde_json_lenient::Value, key: &str) -> Option<&'a str> {
    span["attributes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["key"] == key)
        .and_then(|a| a["value"]["stringValue"].as_str())
}

/// TEL-036: `RUST_LOG` filters the
/// console only. With `RUST_LOG=warn` minvmd still spools its info-level
/// root span, in the caller's trace.
#[test]
fn rust_log_warn_does_not_silence_the_spool() {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("spool");
    let tp = format!("00-{TRACE_ID}-{PARENT_ID}-01");
    status(
        dir.path(),
        &spool,
        &[
            ("MINIMAL_TELEMETRY", "1"),
            ("TRACEPARENT", &tp),
            ("RUST_LOG", "warn"),
        ],
    );
    let spans = spans(&spool_lines(&spool));
    let root = spans
        .iter()
        .find(|(_, s)| s["name"] == "minvmd")
        .unwrap_or_else(|| panic!("RUST_LOG=warn silenced the root span: {spans:?}"));
    assert_eq!(root.1["traceId"], TRACE_ID);
}

/// TEL-032: `minvmd stop` exports a `vm.stop` span under the
/// `minvmd` root (`cmd=stop`), in the caller's trace. A fresh state dir
/// takes the idempotent "not running" return, so no VM is needed.
#[test]
fn a_stop_is_a_vm_stop_span_under_the_minvmd_root() {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("spool");
    let tp = format!("00-{TRACE_ID}-{PARENT_ID}-01");
    minvmd(
        &["stop"],
        0,
        dir.path(),
        &spool,
        &[("MINIMAL_TELEMETRY", "1"), ("TRACEPARENT", &tp)],
    );
    let spans = spans(&spool_lines(&spool));
    let find = |name: &str| {
        spans
            .iter()
            .map(|(_, s)| s)
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("no {name} span in {spans:?}"))
    };
    let (root, stop) = (find("minvmd"), find("vm.stop"));
    assert_eq!(attr(root, "cmd"), Some("stop"));
    assert_eq!(root["parentSpanId"], PARENT_ID);
    assert_eq!(stop["traceId"], TRACE_ID);
    assert_eq!(
        stop["parentSpanId"], root["spanId"],
        "vm.stop under the root"
    );
}
