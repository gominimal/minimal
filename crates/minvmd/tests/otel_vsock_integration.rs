//! Guest telemetry over the VM channel, end to end (spec 25 TEL-034,
//! `docs/specs/25-spec-telemetry/guest-vsock.md`): a real `minvmd run` with
//! telemetry on boots the guest, whose daemon ships its spool records to
//! the supervisor over vsock; the supervisor appends them to the host spool
//! and forwards them, as OTLP/JSON, to the host's endpoint. The boot line
//! carries the forward port and no endpoint.
//!
//! Gates, as `boot_integration`: `#[cfg(minvmd_libkrun)]`, `#[ignore]`,
//! `MINVMD_E2E=1`, and `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`,
//! `MINVMD_INITRAMFS` naming the images (the initramfs must carry a
//! minimald with the sender, i.e. one built from this tree).

#![cfg(minvmd_libkrun)]

mod common;

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use serial_test::serial;

fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// Isolated `XDG_STATE_HOME` under /tmp, short enough for the sockets'
/// `sun_path`.
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// `minvmd <args>` against `state`, with the telemetry environment `env`
/// and every ambient telemetry variable removed first.
fn minvmd(state: &Path, env: &[(&str, String)], args: &[&str]) -> Output {
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

/// An OTLP/HTTP sink on the loopback that records every request body it
/// gets, with its path and content type, and answers `200`.
fn sink() -> (u16, Receiver<(String, String, String)>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = std::io::BufReader::new(stream);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut content_type = String::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.trim_end().is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "content-length" => length = v.trim().parse().unwrap_or(0),
                        "content-type" => content_type = v.trim().to_owned(),
                        _ => {}
                    }
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            let mut stream = reader.into_inner();
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let _ = tx.send((
                path,
                content_type,
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
    });
    (port, rx)
}

/// Every `*.jsonl` line in `spool`.
fn spool_lines(spool: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(spool) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            out.extend(
                std::fs::read_to_string(&p)
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_owned),
            );
        }
    }
    out
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun + kernel/rootfs/initramfs built from this tree"]
fn the_guest_daemons_records_reach_the_host_spool_and_endpoint_over_vsock() {
    if !common::e2e() {
        common::skip_or_fail("otel_vsock_integration", "MINVMD_E2E != 1");
        return;
    }
    for var in [
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "otel_vsock_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    let state = short_state_dir();
    let spool = state.path().join("spool");
    let (port, rx) = sink();
    let env = vec![
        ("MINIMAL_TELEMETRY", "1".to_owned()),
        ("MINIMAL_OTEL_SPOOL_DIR", spool.display().to_string()),
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{port}"),
        ),
        // Must never reach the guest; the host sends it to its own endpoint.
        ("OTEL_EXPORTER_OTLP_HEADERS", "x-host-only=1".to_owned()),
    ];
    let run = minvmd(state.path(), &env, &["run", "--detach", "--timeout", "120"]);
    assert!(
        run.status.success(),
        "minvmd run --detach: {}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    // The guest's `guest.ready` ended before READY, so by now it crossed;
    // the host batches for at most a second.
    let deadline = Instant::now() + Duration::from_secs(20);
    let guest_ready_in_spool = loop {
        let lines = spool_lines(&spool);
        if let Some(l) = lines
            .iter()
            .find(|l| l.contains("\"name\":\"guest.ready\""))
        {
            break l.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no guest.ready in the host spool: {lines:#?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let stop = minvmd(state.path(), &env, &["stop"]);
    assert!(
        stop.status.success(),
        "minvmd stop: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    // The guest's own resource, in the host's spool (TEL-044 sees it).
    assert!(
        guest_ready_in_spool.contains("\"stringValue\":\"minimald\""),
        "the forwarded line keeps the guest's service.name: {guest_ready_in_spool}"
    );
    assert!(
        guest_ready_in_spool
            .contains("{\"key\":\"minimal.forwarded_by\",\"value\":{\"stringValue\":\"minvmd\"}}"),
        "the host stamped its provenance: {guest_ready_in_spool}"
    );
    // The host forwarded it to its endpoint as OTLP/JSON, on the traces path.
    let mut bodies = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let forwarded = loop {
        while let Ok(got) = rx.try_recv() {
            bodies.push(got);
        }
        if let Some((path, ct, body)) = bodies
            .iter()
            .find(|(_, _, b)| b.contains("\"name\":\"guest.ready\""))
        {
            break (path.clone(), ct.clone(), body.clone());
        }
        assert!(
            Instant::now() < deadline,
            "the sink got no guest.ready: {} bodies: {:?}",
            bodies.len(),
            bodies
                .iter()
                .map(|(p, c, b)| (p, c, b.len()))
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    assert_eq!(forwarded.0, "/v1/traces");
    assert_eq!(forwarded.1, "application/json");
    // The boot line: the forward port, no endpoint (TEL-033). The VMM child
    // logs the kernel command line it boots with in the host's minvmd log.
    let logs_dir = state.path().join("minimal/logs");
    let cmdline = std::fs::read_dir(&logs_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("minvmd.log"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .flat_map(|text| {
            text.lines()
                .filter_map(|l| {
                    l.split_once("\"cmdline\":\"")
                        .and_then(|(_, rest)| rest.split_once('"'))
                        .map(|(line, _)| line.to_owned())
                })
                .collect::<Vec<_>>()
        })
        .next()
        .unwrap_or_else(|| panic!("no kernel command line logged under {}", logs_dir.display()));
    // The log names each telemetry token by its key only (TEL-040); the
    // guest's own init line below says where the forward goes.
    assert!(
        cmdline.contains("MINIMAL_OTEL_FORWARD=…"),
        "the boot line carries the forward port: {cmdline}"
    );
    assert!(
        !cmdline.contains("ENDPOINT=") && !cmdline.contains("x-host-only"),
        "no endpoint or header reached the guest: {cmdline}"
    );
    // The console capture goes where the VMM child puts it: `MINVMD_BOOT_LOG`
    // when set (the KVM lane sets it for every harness), else the provider
    // directory's `boot.log`.
    let boot_log_path = std::env::var_os("MINVMD_BOOT_LOG")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            state
                .path()
                .join("minimal/providers/local-minvmd0/boot.log")
        });
    let boot_log = std::fs::read_to_string(&boot_log_path).unwrap_or_default();
    assert!(
        boot_log.contains("traces -> vsock:7353"),
        "the guest's init line names the forward destination ({}): {boot_log}",
        boot_log_path.display()
    );
}
