//! minvmd's OpenTelemetry through the real binary (spec 25: TEL-001,
//! TEL-009, TEL-032, TEL-033, TEL-034, TEL-036): the trace context crosses
//! the `min` → minvmd process boundary, the resource names the service, and
//! with telemetry off minvmd writes nothing.
//!
//! Like `config_cli_integration`, most of these run `minvmd status` or
//! `minvmd stop` against an isolated state dir and need no VM. They read
//! the local OTLP-JSON spool (`MINIMAL_OTEL_SPOOL_DIR`), so no collector is
//! involved either. One, `a_boot_and_stop_share_one_trace_with_the_guest_daemon`
//! (plan T15), boots a VM and is gated like `otel_vsock_integration`.

use std::path::Path;
use std::process::Command;

#[cfg(minvmd_libkrun)]
mod common;

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

// ---- plan T15: a booted VM ----

/// The VM test's own state dir, under /tmp so its sockets fit `sun_path`.
#[cfg(minvmd_libkrun)]
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// `minvmd <args>` against the VM state dir `state` (`HOME` and
/// `XDG_STATE_HOME`), with only `env` for telemetry. Returns the output.
#[cfg(minvmd_libkrun)]
fn minvmd_vm(state: &Path, env: &[(&str, String)], args: &[&str]) -> std::process::Output {
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
    cmd.env("HOME", state).env("XDG_STATE_HOME", state);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawning minvmd")
}

/// Boot a VM on a fresh state dir with `env`, run `during` while it is up,
/// stop it, and return the state dir and the boot line the VMM child
/// composed, as minvmd logs it: the kernel's own parameters as they are,
/// each telemetry token as `KEY=…` (TEL-040). A boot with telemetry off
/// has no telemetry token, so its logged line is the line itself.
#[cfg(minvmd_libkrun)]
fn boot_and_stop(
    env: &[(&str, String)],
    during: impl FnOnce(&Path),
) -> (tempfile::TempDir, String) {
    let state = short_state_dir();
    let run = minvmd_vm(state.path(), env, &["run", "--detach", "--timeout", "120"]);
    assert!(
        run.status.success(),
        "minvmd run --detach: {}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    during(state.path());
    let stop = minvmd_vm(state.path(), env, &["stop"]);
    assert!(
        stop.status.success(),
        "minvmd stop: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let logs = state.path().join("minimal/logs");
    let line = std::fs::read_dir(&logs)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("minvmd.log"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .find_map(|text| {
            text.lines().find_map(|l| {
                l.split_once("\"cmdline\":\"")
                    .and_then(|(_, rest)| rest.split_once('"'))
                    .map(|(line, _)| line.to_owned())
            })
        })
        .unwrap_or_else(|| panic!("no boot line logged under {}", logs.display()));
    (state, line)
}

/// Plan T15 (spec 25 TEL-032, TEL-033, TEL-034, TEL-035): boot a microVM
/// with telemetry on, inside a caller's trace, and stop it. `minvmd run`'s
/// `vm.boot` and `minvmd stop`'s `vm.stop` are in the caller's trace, and so
/// are the guest daemon's spans, which reach the host spool over vsock:
/// `guest.ready` is `vm.boot`'s child, and every guest span in the trace
/// descends from `vm.boot` or, for the guest's shutdown, from `vm.stop`.
/// The boot line, as minvmd logs it, carries only allowlisted telemetry
/// keys, no endpoint and no header (the values are logged as `…`; that the
/// caller's trace crossed is `guest.ready` under `vm.boot`). With telemetry
/// off it is the line of a boot with no telemetry environment at all: the
/// two comparison boots are given the same node proxy port, and the
/// publish generation, drawn fresh for every boot, is the one token
/// compared by key. The byte-for-byte check of the composition is `vm`'s
/// `the_boot_line_carries_only_allowlisted_settings_and_off_is_byte_identical`.
///
/// Gates, as `otel_vsock_integration`: `#[cfg(minvmd_libkrun)]`,
/// `#[ignore]`, `MINVMD_E2E=1`, and `MINVMD_KERNEL_PATH`,
/// `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` naming the images (the
/// initramfs built from this tree).
#[cfg(minvmd_libkrun)]
#[test]
#[serial_test::serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun + kernel/rootfs/initramfs built from this tree"]
fn a_boot_and_stop_share_one_trace_with_the_guest_daemon() {
    const ALLOWED: &[&str] = &[
        "MINIMAL_TELEMETRY",
        "MINIMAL_OTEL_SPOOL",
        "MINIMAL_OTEL_FILTER",
        "MINIMAL_OTEL_TRACES_EXPORTER",
        "MINIMAL_OTEL_LOGS_EXPORTER",
        "MINIMAL_OTEL_FORWARD",
        "TRACEPARENT",
    ];
    if !common::e2e() {
        common::skip_or_fail("otel_integration", "MINVMD_E2E != 1");
        return;
    }
    for var in [
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "otel_integration: {var} must be set when MINVMD_E2E=1"
        );
    }

    // Telemetry on, in the caller's trace.
    let spool_root = tempfile::tempdir().unwrap();
    let spool = spool_root.path().join("spool");
    let tp = format!("00-{TRACE_ID}-{PARENT_ID}-01");
    let on = vec![
        ("MINIMAL_TELEMETRY", "1".to_owned()),
        ("MINIMAL_OTEL_SPOOL_DIR", spool.display().to_string()),
        ("TRACEPARENT", tp.clone()),
        // Neither may reach the guest.
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://u:s3cr3tPW@127.0.0.1:9".to_owned(),
        ),
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            "x-host-only=s3cr3tKEY".to_owned(),
        ),
    ];
    let (_state, on_line) = boot_and_stop(&on, |_| {
        // `guest.ready` ended before READY; the door batches for at most a
        // second, so wait for it in the host spool before stopping.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !spans(&spool_lines(&spool))
            .iter()
            .any(|(_, s)| s["name"] == "guest.ready")
        {
            assert!(
                std::time::Instant::now() < deadline,
                "no guest.ready reached the host spool"
            );
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    });
    let all = spans(&spool_lines(&spool));
    let in_trace: Vec<&(String, serde_json_lenient::Value)> = all
        .iter()
        .filter(|(_, s)| s["traceId"] == TRACE_ID)
        .collect();
    let find = |name: &str| {
        in_trace
            .iter()
            .find(|(_, s)| s["name"] == name)
            .unwrap_or_else(|| panic!("no {name} span in the caller's trace: {all:#?}"))
    };
    let boot = &find("vm.boot").1;
    let stop = &find("vm.stop").1;
    let ready = find("guest.ready");
    assert_eq!(ready.0, "minimald", "guest.ready is the guest daemon's");
    assert_eq!(
        ready.1["parentSpanId"], boot["spanId"],
        "guest.ready is vm.boot's child"
    );
    // Every guest span in the trace descends from the host's: from vm.boot
    // (the guest's boot) or from vm.stop (its shutdown, asked by the stop).
    let by_id = |id: &serde_json_lenient::Value| in_trace.iter().find(|(_, s)| s["spanId"] == *id);
    for (service, span) in in_trace.iter().filter(|(svc, _)| svc == "minimald") {
        let mut at = span;
        let mut hops = 0;
        while at["spanId"] != boot["spanId"] && at["spanId"] != stop["spanId"] {
            at = &by_id(&at["parentSpanId"])
                .unwrap_or_else(|| {
                    panic!("{service} span {span} reaches neither vm.boot nor vm.stop")
                })
                .1;
            hops += 1;
            assert!(hops < 32, "a parent loop at {span}");
        }
    }

    // The boot line the guest got: allowlisted keys only, nothing secret.
    let telemetry_keys: Vec<&str> = on_line
        .split_whitespace()
        .filter_map(|w| w.split_once('=').map(|(k, _)| k))
        .filter(|k| {
            (k.starts_with("MINIMAL_") && !k.starts_with("MINIMALD_"))
                || k.starts_with("OTEL_")
                || *k == "TRACEPARENT"
        })
        .collect();
    for key in &telemetry_keys {
        assert!(ALLOWED.contains(key), "{key} crossed: {on_line}");
    }
    for key in ["MINIMAL_TELEMETRY", "MINIMAL_OTEL_FORWARD", "TRACEPARENT"] {
        assert!(telemetry_keys.contains(&key), "{key} missing: {on_line}");
    }
    for leak in [
        "s3cr3t",
        "x-host-only",
        "ENDPOINT",
        "HEADERS",
        "127.0.0.1:9",
    ] {
        assert!(
            !on_line.contains(leak),
            "{leak} reached the guest: {on_line}"
        );
    }

    // Telemetry off: the line of a boot with no telemetry environment.
    let off = vec![
        ("DO_NOT_TRACK", "1".to_owned()),
        ("MINIMAL_TELEMETRY", "1".to_owned()),
        ("TRACEPARENT", tp),
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://127.0.0.1:9".to_owned(),
        ),
    ];
    // Both boots get the same node proxy port (the operator's override),
    // so the lines can differ only by telemetry and the generation.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let mut off = off;
    off.push(("MINVMD_NODE_PROXY_PORT", port.clone()));
    let (_off_state, off_line) = boot_and_stop(&off, |_| {});
    let bare = vec![("MINVMD_NODE_PROXY_PORT", port)];
    let (_bare_state, bare_line) = boot_and_stop(&bare, |_| {});
    let generation_by_key = |line: &str| {
        line.split(' ')
            .map(|w| match w.split_once('=') {
                Some(("MINIMALD_PUBLISH_GENERATION", _)) => {
                    "MINIMALD_PUBLISH_GENERATION=…".to_owned()
                }
                _ => w.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(
        generation_by_key(&off_line),
        generation_by_key(&bare_line),
        "telemetry off changed the boot line"
    );
    assert!(
        !off_line.contains("MINIMAL_TELEMETRY") && !off_line.contains("TRACEPARENT"),
        "{off_line}"
    );
}
