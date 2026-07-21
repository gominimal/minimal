//! The daemon's contribution to a `min bug` diagnostic bundle.
//!
//! Serves the `DiagBundleTarZst` streaming subsystem: reads one JSON
//! [`DiagBundleRequest`], then streams back a zstd-compressed tar of the
//! daemon's own view — logs, state listings, session records (redacted),
//! process/network/disk state. Served identically by the native Linux daemon
//! and the in-VM pid-1 instance; `meta.json` says which one answered.
//!
//! The archive is written through [`diagnostics::BundleWriter`] in stream
//! (rootless) mode, so the guest bundle carries the same `manifest.json` as the
//! host one: collector failures never abort the stream, they land in the
//! manifest's error list. A half-broken daemon still reports everything it can,
//! plus why the rest is missing.
//!
//! What lives here is policy — which paths, which markers, which env names,
//! where entries land in the archive. Every generic mechanic (the `/proc`
//! walks, the redaction, the tail caps, the socket join) comes from the
//! `diagnostics` crate, which the CLI-side collector shares.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use minimald_rpc::DiagBundleRequest;
use russh::{Channel as RuChannel, server::Msg};
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use diagnostics::redact::{masked_process_env, redact_json};
use diagnostics::{BundleSink, BundleWriter, LOG_TAIL_CAP, Redaction};

use crate::ChannelConfig;
use crate::server::ServerStateHandle;

/// Longest request body accepted before the read is abandoned. The body is a
/// two-field JSON object; anything larger is a client bug or an attempt to
/// make the daemon buffer for free.
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
/// Ceiling on the caller-controlled per-log tail.
const MAX_LOG_TAIL_BYTES: u64 = 64 * 1024 * 1024;
/// Rotated log files bundled, newest first.
const LOG_FILES_MAX: usize = 5;
/// Entry cap for the recursive state-dir listing.
const LISTING_MAX_ENTRIES: usize = 100_000;
/// Per-collector deadline. A wedged daemon is exactly when this bundle is
/// wanted, so no single collector may hold the stream open indefinitely.
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(30);
/// Duplex buffer between the bundle writer and the channel pump.
const PIPE_BUF: usize = 256 * 1024;
/// The gvproxy management endpoint, reachable only from inside the switch
/// fabric (i.e. from the guest).
const GVPROXY_MGMT: (&str, u16) = ("192.168.127.254", 8080);

/// argv0 basenames marking a process as part of *this daemon's* family.
///
/// The daemon's policy, not the CLI's: inside the microVM there is no `minvmd`,
/// no `__krun-vmm` and no `gvproxy` to find — those run on the host and are the
/// host collector's business — while a task child running `min` in the guest is
/// this daemon's business. The matching mechanic (argv0 basename, never a
/// substring) lives in [`diagnostics::procs`], which takes this list as an
/// argument.
const PROC_MARKERS: &[&str] = &["minimald", "min", "minimal"];

/// Env vars whose *values* are safe and useful to include verbatim; everything
/// else is reported by name only. The daemon carries its own list rather than
/// sharing the CLI's because the interesting names differ — this one answers
/// "which mode booted, and why is logging off".
const ENV_VALUE_ALLOWLIST_EXACT: &[&str] = &["RUST_LOG", "HOME", "PATH", "TERM", "SHELL"];
const ENV_VALUE_ALLOWLIST_PREFIXES: &[&str] = &["MINIMAL_", "MINIMALD_", "MINVMD_", "XDG_"];

/// Returns true when the named env var's value may be captured verbatim.
/// A sensitive-shaped name always loses to the allowlist — `MINIMALD_TOKEN`
/// matches the project prefix but must never leave the machine.
fn is_env_value_allowlisted(name: &str) -> bool {
    if diagnostics::redact::is_sensitive_key(name) {
        return false;
    }
    ENV_VALUE_ALLOWLIST_EXACT.contains(&name)
        || ENV_VALUE_ALLOWLIST_PREFIXES
            .iter()
            .any(|p| name.starts_with(p))
}

/// Runs one collector future with [`COLLECTOR_TIMEOUT`]; failure or timeout is
/// recorded in the manifest and the run continues. A macro (not a function) so
/// the future's borrow of the writer ends before the error-recording arms
/// re-borrow it.
macro_rules! collect_step {
    ($w:expr, $name:expr, $fut:expr) => {{
        let name: String = $name.into();
        let started = std::time::Instant::now();
        let failure = match tokio::time::timeout(COLLECTOR_TIMEOUT, $fut).await {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(_) => Some(format!("timed out after {COLLECTOR_TIMEOUT:?}")),
        };
        if let Some(error) = failure {
            tracing::warn!(collector = %name, %error, "diag collector failed");
            $w.error(name, error, started.elapsed());
        }
    }};
}

pub(crate) async fn serve_stream_diag_bundle(
    s: ServerStateHandle,
    _config: ChannelConfig,
    mut c: RuChannel<Msg>,
) {
    if let Err(msg) = stream_diag_bundle(&s, &mut c).await {
        let _ = c.extended_data_bytes(1, msg).await;
    }
    let _ = c.close().await;
}

/// Reads the request, then streams the bundle. On failure returns the
/// human-readable message to relay over the channel's extended-data stream.
///
/// Everything that can fail *before* the first payload byte — the request read
/// and its parse — happens up front, so a client that reads zero payload bytes
/// can treat the extended data as the whole story.
async fn stream_diag_bundle(s: &ServerStateHandle, c: &mut RuChannel<Msg>) -> Result<(), String> {
    let req = read_request(c).await?;

    // `async_tar::Builder` requires `W: Sync`; the channel writer is not. Same
    // duplex-pipe pattern as the workspace-files upload, reversed direction.
    let (tx, mut rx) = tokio::io::duplex(PIPE_BUF);
    let build = {
        let s = s.clone();
        tokio::task::spawn(async move { build_bundle(&s, &req, tx).await })
    };

    let mut writer = c.make_writer();
    let copy_result = tokio::io::copy(&mut rx, &mut writer).await;
    let shutdown_result = writer.shutdown().await;
    // The read half must be gone before waiting on the build task: if the copy
    // failed mid-stream (client vanished) the task is still writing, and only a
    // dropped `rx` turns its next write into `BrokenPipe` instead of an
    // indefinite block on the full duplex buffer.
    drop(rx);
    copy_result.map_err(|e| format!("streaming diag bundle: {e}"))?;

    match build.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("building diag bundle: {e}")),
        Err(e) => return Err(format!("diag bundle task panicked: {e}")),
    }
    shutdown_result.map_err(|e| format!("closing diag stream: {e}"))?;
    Ok(())
}

/// Reads the request body, bounded: one byte past the limit is enough to know
/// the body is oversized, and refusing there means an unbounded client write
/// can never become an unbounded daemon allocation.
async fn read_request(c: &mut RuChannel<Msg>) -> Result<DiagBundleRequest, String> {
    let mut buf = Vec::with_capacity(256);
    c.make_reader()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("reading diag request: {e}"))?;
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err(format!(
            "diag request too large: over {MAX_REQUEST_BYTES} bytes"
        ));
    }
    // An empty body is a valid request for the documented defaults.
    if buf.is_empty() {
        return Ok(DiagBundleRequest::default());
    }
    serde_json::from_slice(&buf).map_err(|e| format!("parsing diag request: {e}"))
}

/// The per-log tail cap this run honors: the daemon default when the request
/// leaves it at 0, otherwise the caller's value clamped to the server ceiling.
///
/// The clamp is not politeness. `BundleWriter::add_file_tail` seeks
/// `-(cap as i64)` from the end, so an unclamped `u64` is both an unbounded
/// read and — past `i64::MAX` — a nonsense seek.
fn log_tail_cap(req: &DiagBundleRequest) -> u64 {
    match req.log_tail_bytes {
        0 => LOG_TAIL_CAP,
        requested => requested.min(MAX_LOG_TAIL_BYTES),
    }
}

/// Runs every collector into a rootless streaming bundle, finishing with the
/// manifest. Individual collectors fail into the manifest; only a failure of
/// the archive itself aborts.
async fn build_bundle(
    s: &ServerStateHandle,
    req: &DiagBundleRequest,
    tx: tokio::io::DuplexStream,
) -> Result<(), String> {
    let created_at = chrono::Utc::now();
    let started = std::time::Instant::now();
    let state_dir = s
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .as_std_path()
        .to_path_buf();
    // The daemon is always in its own family whatever argv0 says, so it is
    // named to the per-process captures explicitly rather than matched.
    let self_pid = [std::process::id()];
    let mut w = BundleWriter::stream(tx, version::LONG_VERSION);

    collect_step!(w, "meta", meta(&mut w, s));
    collect_step!(w, "logs", logs(&mut w, &state_dir, log_tail_cap(req)));
    collect_step!(
        w,
        "state-listing",
        state_listing(&mut w, &state_dir, req.include_state_listing)
    );
    collect_step!(w, "sessions", sessions(&mut w, &state_dir));
    collect_step!(w, "env", env(&mut w));
    // Incident captures: pure `/proc`, since the microVM rootfs has no `ps`,
    // `lsof`, `ss` or `ip`. The mechanics are the ones the host bundle uses.
    collect_step!(
        w,
        "proc",
        diagnostics::procs::all_processes(&mut w, "", PROC_MARKERS)
    );
    collect_step!(
        w,
        "proc.hang-triage",
        diagnostics::procs::hang_triage_including(&mut w, "", PROC_MARKERS, &self_pid)
    );
    collect_step!(
        w,
        "proc.sockets",
        diagnostics::procs::open_sockets(&mut w, "", PROC_MARKERS, &self_pid)
    );
    collect_step!(
        w,
        "net.listening",
        diagnostics::net::proc_net_tables(
            &mut w,
            "",
            "listening",
            diagnostics::net::PROC_NET_SOCKET_TABLES
        )
    );
    collect_step!(
        w,
        "net.interfaces",
        diagnostics::net::proc_net_tables(&mut w, "", "interfaces", &["dev"])
    );
    // Routing *and* addresses: `fib_trie` carries the local address picture the
    // host's `ip addr` gives on the other side of the switch.
    collect_step!(
        w,
        "net.routes",
        diagnostics::net::proc_net_tables(&mut w, "", "routes", &["route", "fib_trie"])
    );
    if s.in_microvm().await {
        collect_step!(w, "net.gvproxy", gvproxy_probe(&mut w));
    }
    collect_step!(w, "disk", disk(&mut w, &state_dir));

    w.finish(created_at, started.elapsed())
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── collectors ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Meta {
    version: &'static str,
    long_version: &'static str,
    stdlib_version: &'static str,
    pid: u32,
    uptime_secs: Option<f64>,
    in_microvm: bool,
    state_volume_mounted: bool,
    state_dir: String,
}

async fn meta<W: BundleSink>(
    w: &mut BundleWriter<W>,
    s: &ServerStateHandle,
) -> Result<(), anyhow::Error> {
    let uptime = tokio::fs::read_to_string("/proc/uptime").await.ok();
    let info = Meta {
        version: version::VERSION,
        long_version: version::LONG_VERSION,
        stdlib_version: stdlib::VERSION,
        pid: std::process::id(),
        uptime_secs: uptime.and_then(|s| s.split_whitespace().next()?.parse().ok()),
        in_microvm: s.in_microvm().await,
        state_volume_mounted: s.state_volume_mounted().await,
        state_dir: s.minimal_state_dir().await.to_string(),
    };
    let json = serde_json::to_vec_pretty(&info).context("serializing meta")?;
    w.add_bytes("meta.json", &json, Redaction::None).await
}

async fn logs<W: BundleSink>(
    w: &mut BundleWriter<W>,
    state_dir: &Path,
    cap: u64,
) -> Result<(), anyhow::Error> {
    let log_dir = state_dir.join("logs");
    // Absence and inaccessibility are different facts: "no log directory" may
    // only be claimed on a real NotFound, never on EACCES or an I/O error.
    match tokio::fs::metadata(&log_dir).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            w.skip(
                "logs/",
                "no log directory — this daemon has never run detached",
            );
            return Ok(());
        }
        Err(e) => {
            w.skip("logs/", format!("unreadable: {e}"));
            return Ok(());
        }
        Ok(_) => {}
    }
    // Only this daemon's own rotated logs: the state dir can be shared with
    // minvmd (native installs), whose files belong to the host-side collector,
    // not the daemon's self-view.
    let files = diagnostics::newest_rotated(&log_dir, "minimald.log", LOG_FILES_MAX).await;
    if files.is_empty() {
        w.skip("logs/minimald.log*", "no files with this prefix");
        return Ok(());
    }
    for path in files {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let dest = format!("logs/{name}");
        // `add_file_tail` opens O_NOFOLLOW and fstats the descriptor: the in-VM
        // daemon reads a volume guest tasks can write, so a symlink named
        // `minimald.log.*` must not steer an unrelated target into the bundle.
        if let Err(e) = w.add_file_tail(&dest, &path, cap).await {
            w.skip(&dest, format!("unreadable: {e:#}"));
        }
    }
    Ok(())
}

async fn state_listing<W: BundleSink>(
    w: &mut BundleWriter<W>,
    state_dir: &Path,
    include: bool,
) -> Result<(), anyhow::Error> {
    if !include {
        w.skip("state-listing.txt", "not requested");
        return Ok(());
    }
    // Up to 100k synchronous fs ops — keep them off the RPC-serving runtime,
    // so a wedged filesystem strands a blocking thread and not the worker whose
    // collect_step! timeout is the failsafe.
    let dir = state_dir.to_path_buf();
    let listing =
        tokio::task::spawn_blocking(move || diagnostics::listing(&dir, LISTING_MAX_ENTRIES))
            .await
            .context("listing worker")?
            .context("listing state dir")?;
    if listing.truncated {
        w.skip(
            "state-listing.txt (tail)",
            format!("listing cap of {LISTING_MAX_ENTRIES} entries reached"),
        );
    }
    w.add_bytes(
        "state-listing.txt",
        listing.text.as_bytes(),
        Redaction::ListingOnly,
    )
    .await
}

async fn sessions<W: BundleSink>(
    w: &mut BundleWriter<W>,
    state_dir: &Path,
) -> Result<(), anyhow::Error> {
    let sessions_dir = state_dir.join("sessions");
    // The index maps short directory names to session UUIDs — no user data, so
    // it travels verbatim.
    match tokio::fs::read(sessions_dir.join("index.json")).await {
        Ok(bytes) => {
            w.add_bytes("sessions/index.json", &bytes, Redaction::None)
                .await?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow::anyhow!("reading sessions/index.json: {e}")),
    }
    let Ok(mut entries) = tokio::fs::read_dir(&sessions_dir).await else {
        return Ok(());
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let short = entry.file_name().to_string_lossy().into_owned();
        // An absent file is always explainable (the manifest contract): a
        // genuinely-missing record is silent, but a read failure or an
        // unparseable-and-withheld record leaves a note in its place rather
        // than vanishing.
        let raw = match tokio::fs::read(entry.path().join("record.json")).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                w.skip(
                    format!("sessions/{short}/record.json"),
                    format!("unreadable: {e}"),
                );
                continue;
            }
        };
        // Records can hold user env-var values (loadout vars); mask
        // secret-shaped content before it leaves the machine.
        match serde_json::from_slice::<serde_json::Value>(&raw) {
            Ok(mut value) => {
                redact_json(&mut value);
                let json = serde_json::to_vec_pretty(&value).context("serializing record")?;
                w.add_bytes(
                    &format!("sessions/{short}/record.json.redacted"),
                    &json,
                    Redaction::Keys,
                )
                .await?;
            }
            // Withheld: it cannot be redacted safely, so it does not travel.
            Err(e) => w.skip(
                format!("sessions/{short}/record.json"),
                format!("does not parse as JSON, cannot redact safely: {e}"),
            ),
        }
    }
    Ok(())
}

/// The daemon's own environment, values masked by the allowlist policy above.
/// Answers "which mode booted, why is logging off" — `RUST_LOG`, the
/// `MINIMALD_*` detach markers, the resolved dirs.
async fn env<W: BundleSink>(w: &mut BundleWriter<W>) -> Result<(), anyhow::Error> {
    let env = masked_process_env(is_env_value_allowlisted);
    let json = serde_json::to_vec_pretty(&env).context("serializing env")?;
    w.add_bytes("env.json", &json, Redaction::Keys).await
}

#[derive(Serialize)]
struct GvproxyProbe {
    endpoint: String,
    connect: String,
    http_head: Option<String>,
}

/// Reachability of the gvproxy management endpoint from inside the VM — the
/// single NAT hop every guest egress depends on.
async fn gvproxy_probe<W: BundleSink>(w: &mut BundleWriter<W>) -> Result<(), anyhow::Error> {
    let (host, port) = GVPROXY_MGMT;
    let endpoint = format!("{host}:{port}");
    let probe = match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let http_head = async {
                stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.ok()?;
                let mut head = vec![0u8; 1024];
                let n = stream.read(&mut head).await.ok()?;
                Some(String::from_utf8_lossy(&head[..n]).into_owned())
            };
            let http_head = tokio::time::timeout(Duration::from_secs(2), http_head)
                .await
                .ok()
                .flatten();
            GvproxyProbe {
                endpoint,
                connect: "ok".to_string(),
                http_head,
            }
        }
        Ok(Err(e)) => GvproxyProbe {
            endpoint,
            connect: e.to_string(),
            http_head: None,
        },
        Err(_) => GvproxyProbe {
            endpoint,
            connect: "timed out after 2s".to_string(),
            http_head: None,
        },
    };
    let json = serde_json::to_vec_pretty(&probe).context("serializing gvproxy probe")?;
    w.add_bytes("net/gvproxy.json", &json, Redaction::None)
        .await
}

#[derive(Serialize)]
struct Filesystem {
    path: String,
    total_bytes: Option<u64>,
    free_bytes: Option<u64>,
}

#[derive(Serialize)]
struct Disk {
    filesystems: Vec<Filesystem>,
    mounts: String,
}

async fn disk<W: BundleSink>(
    w: &mut BundleWriter<W>,
    state_dir: &Path,
) -> Result<(), anyhow::Error> {
    let info = Disk {
        filesystems: [state_dir, Path::new("/")]
            .into_iter()
            .map(|path| {
                let usage = diagnostics::disk_usage(path);
                Filesystem {
                    path: path.display().to_string(),
                    total_bytes: usage.map(|u| u.total_bytes),
                    free_bytes: usage.map(|u| u.free_bytes),
                }
            })
            .collect(),
        mounts: tokio::fs::read_to_string("/proc/mounts")
            .await
            .unwrap_or_else(|e| format!("<unreadable: {e}>")),
    };
    let json = serde_json::to_vec_pretty(&info).context("serializing disk info")?;
    w.add_bytes("disk.json", &json, Redaction::None).await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use minimald_rpc::DIAG_BUNDLE_SUBSYSTEM;
    use russh::ChannelMsg;

    use super::*;
    use crate::test_harness::TestServer;

    /// Drains a diag-bundle channel, returning the payload and the extended
    /// data (stream 1) separately — the two halves of the R6.4 contract.
    async fn drain(mut channel: russh::Channel<russh::client::Msg>) -> (Vec<u8>, String) {
        let mut payload = Vec::new();
        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => payload.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                _ => {}
            }
        }
        (payload, String::from_utf8_lossy(&stderr).into_owned())
    }

    /// Requests a bundle over the real subsystem with `body` as the raw
    /// request, returning the streamed payload and any extended data.
    async fn request_bundle(server: &TestServer, body: &[u8]) -> (Vec<u8>, String) {
        let mut client = server.connect().await;
        let channel = client.open_subsystem(DIAG_BUNDLE_SUBSYSTEM, &[]).await;
        channel.data(body).await.unwrap();
        channel.eof().await.unwrap();
        drain(channel).await
    }

    /// Fetches a default bundle and decodes it to `path -> contents`.
    async fn fetch_bundle(server: &TestServer) -> BTreeMap<String, Vec<u8>> {
        let body = serde_json::to_vec(&DiagBundleRequest::default()).unwrap();
        let (payload, stderr) = request_bundle(server, &body).await;
        assert!(!payload.is_empty(), "no bundle streamed; stderr: {stderr}");

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&payload[..]);
        let out = tempfile::TempDir::new().unwrap();
        async_tar::Archive::new(decoder)
            .unpack(out.path().to_path_buf())
            .await
            .unwrap();

        let mut files = BTreeMap::new();
        collect_files(out.path(), out.path(), &mut files);
        files
    }

    fn collect_files(base: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(base, &path, files);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy().into();
                files.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }

    fn manifest(files: &BTreeMap<String, Vec<u8>>) -> serde_json::Value {
        serde_json::from_slice(&files["manifest.json"]).expect("manifest is valid JSON")
    }

    #[tokio::test]
    async fn diag_bundle_streams_meta_and_manifest() {
        let server = TestServer::new().await;
        let files = fetch_bundle(&server).await;

        let meta: serde_json::Value = serde_json::from_slice(&files["meta.json"]).unwrap();
        assert_eq!(meta["version"], version::VERSION);
        assert_eq!(meta["in_microvm"], false);
        assert_eq!(meta["pid"], std::process::id());

        // The bundle describes itself: every entry above is manifested, and a
        // healthy daemon collects without errors.
        let manifest = manifest(&files);
        assert_eq!(manifest["schema_version"], 1);
        assert_eq!(manifest["version"], version::LONG_VERSION);
        assert!(
            manifest["errors"].as_array().unwrap().is_empty(),
            "healthy test server should collect cleanly, got: {}",
            manifest["errors"]
        );
        let collected: Vec<&str> = manifest["collected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert!(collected.contains(&"meta.json"), "{collected:?}");

        for entry in [
            "state-listing.txt",
            "proc.txt",
            "net/listening.txt",
            "disk.json",
            "env.json",
        ] {
            assert!(
                files.contains_key(entry),
                "missing {entry}: {:?}",
                files.keys()
            );
        }
        // Not in a microVM: no gvproxy probe entry.
        assert!(!files.contains_key("net/gvproxy.json"));
    }

    /// R6.6: the guest-side incident trio, all of it binary-free `/proc`.
    #[tokio::test]
    async fn diag_bundle_captures_the_incident_trio_and_env() {
        let server = TestServer::new().await;
        // Keep a live connection so the daemon's own socket fds are open while
        // the bundle is collected.
        let _client = server.connect().await;
        let files = fetch_bundle(&server).await;
        let pid = std::process::id();

        let routes = String::from_utf8_lossy(&files["net/routes.txt"]).into_owned();
        assert!(routes.contains("/proc/net/route"), "{routes}");
        assert!(
            routes.contains("/proc/net/fib_trie"),
            "addresses ride along with routes: {routes}"
        );

        let stack = files
            .get(&format!("proc/{pid}.stack.txt"))
            .expect("the daemon hang-triages itself whatever its argv0 says");
        let stack = String::from_utf8_lossy(stack);
        assert!(stack.contains("=== wchan ==="), "{stack}");
        assert!(stack.contains("=== fds ==="), "{stack}");

        let sockets = String::from_utf8_lossy(&files["proc/sockets.txt"]).into_owned();
        let joined: Vec<&str> = sockets
            .lines()
            .skip(1)
            .filter(|line| line.starts_with(&format!("{pid}\t")))
            .collect();
        assert!(!joined.is_empty(), "no fds for our own pid: {sockets}");
        assert!(
            joined
                .iter()
                .any(|line| line.split('\t').nth(3) == Some("unix")),
            "the in-process ssh transport is a unix socket and must resolve \
             against /proc/net/unix: {joined:?}"
        );

        // Every value the policy does not allow is masked, names always kept.
        let env: BTreeMap<String, String> = serde_json::from_slice(&files["env.json"]).unwrap();
        assert!(!env.is_empty());
        for (name, value) in &env {
            assert!(
                is_env_value_allowlisted(name) || value.starts_with("<redacted:len="),
                "{name} must be masked, got: {value}"
            );
        }
    }

    /// The daemon's env policy: a project-prefixed name that is also
    /// secret-shaped loses to the sensitive-key rule.
    #[test]
    fn env_allowlist_masks_secret_shaped_names() {
        for name in ["RUST_LOG", "MINIMALD_DETACHED", "MINIMAL_STATE_DIR", "HOME"] {
            assert!(is_env_value_allowlisted(name), "{name} should be allowed");
        }
        for name in [
            "MINIMALD_TOKEN",
            "MINIMALD_API_KEY",
            "MINIMAL_AUTH_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "LANG",
        ] {
            assert!(!is_env_value_allowlisted(name), "{name} must not be");
        }
    }

    #[tokio::test]
    async fn diag_bundle_logs_exclude_other_daemons_files() {
        let server = TestServer::new().await;
        let state_dir = server.state.minimal_state_dir().await;
        let log_dir = state_dir.as_utf8_path().as_std_path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        // minvmd shares the state dir on native installs; its logs must not
        // crowd out the daemon's own.
        for name in [
            "minimald.log.2026-07-14",
            "minimald.log.2026-07-15",
            "minvmd.log.2026-07-01",
            "minvmd.log.2026-07-02",
            "minvmd.log.2026-07-03",
            "minvmd.log.2026-07-04",
            "minvmd.log.2026-07-05",
        ] {
            std::fs::write(log_dir.join(name), name).unwrap();
        }

        let files = fetch_bundle(&server).await;
        assert!(files.contains_key("logs/minimald.log.2026-07-15"));
        assert!(files.contains_key("logs/minimald.log.2026-07-14"));
        assert!(
            !files.keys().any(|k| k.starts_with("logs/minvmd")),
            "minvmd logs belong to the host-side collector, got: {:?}",
            files.keys().collect::<Vec<_>>()
        );
    }

    /// A symlink planted in the log dir must not steer its target into the
    /// bundle — and the manifest must say so rather than staying silent.
    #[tokio::test]
    async fn diag_bundle_refuses_symlinked_logs() {
        let server = TestServer::new().await;
        let state_dir = server.state.minimal_state_dir().await;
        let log_dir = state_dir.as_utf8_path().as_std_path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        let secret = log_dir.join("secret.key");
        std::fs::write(&secret, "private key material").unwrap();
        std::os::unix::fs::symlink(&secret, log_dir.join("minimald.log.evil")).unwrap();

        let files = fetch_bundle(&server).await;
        assert!(
            !files.contains_key("logs/minimald.log.evil"),
            "symlinked log must not travel: {:?}",
            files.keys().collect::<Vec<_>>()
        );
        let skipped = manifest(&files)["skipped"].to_string();
        assert!(
            skipped.contains("minimald.log.evil"),
            "the refusal is recorded, not silent: {skipped}"
        );
    }

    #[tokio::test]
    async fn diag_bundle_redacts_session_records() {
        let server = TestServer::new().await;
        {
            let mut client = server.connect().await;
            crate::test_harness::create_configured_session(&mut client, "diag-test", "/tmp").await;
        }
        let files = fetch_bundle(&server).await;

        assert!(files.contains_key("sessions/index.json"));
        let record = files
            .iter()
            .find(|(path, _)| path.ends_with("record.json.redacted"))
            .map(|(_, contents)| contents)
            .expect("a redacted session record should be bundled");
        let value: serde_json::Value = serde_json::from_slice(record).unwrap();
        assert_eq!(value["name"], "diag-test", "non-secret fields survive");
    }

    /// R6.4: a request that fails before streaming starts yields extended data
    /// and zero payload bytes, never a truncated archive.
    #[tokio::test]
    async fn malformed_request_reports_on_extended_data_with_no_payload() {
        let server = TestServer::new().await;
        let (payload, stderr) = request_bundle(&server, b"{not json").await;
        assert!(payload.is_empty(), "no payload may precede a request error");
        assert!(stderr.contains("parsing diag request"), "got: {stderr}");
    }

    /// R6.3: an oversized body is refused rather than buffered.
    #[tokio::test]
    async fn oversized_request_body_is_rejected() {
        let server = TestServer::new().await;
        let body = vec![b' '; (MAX_REQUEST_BYTES + 4096) as usize];
        let (payload, stderr) = request_bundle(&server, &body).await;
        assert!(payload.is_empty(), "no payload for a refused request");
        assert!(stderr.contains("diag request too large"), "got: {stderr}");
    }

    /// R6.3: the caller-controlled tail is clamped to the server's ceiling; 0
    /// means the daemon's default.
    #[test]
    fn log_tail_is_clamped_to_the_server_cap() {
        let with = |bytes| log_tail_cap(&DiagBundleRequest::default().with_log_tail_bytes(bytes));
        assert_eq!(with(0), LOG_TAIL_CAP, "0 means the daemon default");
        assert_eq!(with(4096), 4096, "a modest request is honored");
        assert_eq!(with(u64::MAX), MAX_LOG_TAIL_BYTES, "clamped, never wrapped");
        assert!(
            MAX_LOG_TAIL_BYTES < i64::MAX as u64,
            "the cap must keep the tail seek representable"
        );
    }

    /// `include_state_listing: false` must skip the listing and say so.
    #[tokio::test]
    async fn state_listing_is_optional() {
        let server = TestServer::new().await;
        let body =
            serde_json::to_vec(&DiagBundleRequest::default().with_state_listing(false)).unwrap();
        let (payload, stderr) = request_bundle(&server, &body).await;
        assert!(!payload.is_empty(), "stderr: {stderr}");

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&payload[..]);
        let out = tempfile::TempDir::new().unwrap();
        async_tar::Archive::new(decoder)
            .unpack(out.path().to_path_buf())
            .await
            .unwrap();
        let mut files = BTreeMap::new();
        collect_files(out.path(), out.path(), &mut files);

        assert!(!files.contains_key("state-listing.txt"));
        assert!(
            manifest(&files)["skipped"]
                .to_string()
                .contains("state-listing.txt"),
            "an omission is recorded"
        );
    }
}
