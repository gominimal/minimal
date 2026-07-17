//! The daemon's contribution to a `min bug` diagnostic bundle.
//!
//! Serves the `DiagBundleTarZst` streaming subsystem: reads one JSON
//! [`DiagBundleRequest`], then streams back a zstd-compressed tar of the
//! daemon's own view — logs, state listings, session records (redacted),
//! process/network/disk state. Served identically by the native Linux daemon
//! and the in-VM pid-1 instance; `meta.json` says which one answered.
//!
//! Collector failures never abort the stream: they accumulate into an
//! `errors.json` entry written last, so a half-broken daemon still reports
//! everything it can plus why the rest is missing.

use async_tar::{Builder, EntryType, Header};
use minimald_rpc::DiagBundleRequest;
use russh::{Channel as RuChannel, server::Msg};
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::ChannelConfig;
use crate::server::ServerStateHandle;

/// Default per-log-file tail cap when the request leaves it at 0.
const DEFAULT_LOG_TAIL_BYTES: u64 = 5 * 1024 * 1024;
/// Rotated log files bundled per prefix, newest first.
const LOG_FILES_MAX: usize = 5;
/// Entry cap for the recursive state-dir listing.
const LISTING_MAX_ENTRIES: usize = 100_000;
/// The gvproxy management endpoint, reachable only from inside the switch
/// fabric (i.e. from the guest).
const GVPROXY_MGMT: (&str, u16) = ("192.168.127.254", 8080);

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
async fn stream_diag_bundle(s: &ServerStateHandle, c: &mut RuChannel<Msg>) -> Result<(), String> {
    let mut buf = Vec::with_capacity(256);
    c.make_reader()
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("reading diag request: {e}"))?;
    let req: DiagBundleRequest = if buf.is_empty() {
        DiagBundleRequest::default()
    } else {
        serde_json::from_slice(&buf).map_err(|e| format!("parsing diag request: {e}"))?
    };

    // async_tar::Builder requires W: Sync; the channel writer is not. Same
    // duplex-pipe pattern as the workspace-files upload, reversed direction.
    const PIPE_BUF: usize = 256 * 1024;
    let (tx, mut rx) = tokio::io::duplex(PIPE_BUF);

    let build = {
        let s = s.clone();
        tokio::task::spawn(async move {
            let encoder = async_compression::tokio::write::ZstdEncoder::new(tx);
            let mut tar = Builder::new(encoder);
            let errors = collect_into_tar(&s, &req, &mut tar).await;
            let errors_json = serde_json::to_vec_pretty(&errors).unwrap_or_else(|e| {
                format!("[{{\"error\": \"serializing errors: {e}\"}}]").into_bytes()
            });
            append_bytes(&mut tar, "errors.json", &errors_json)
                .await
                .map_err(|e| format!("adding errors.json: {e}"))?;
            let mut encoder = tar
                .into_inner()
                .await
                .map_err(|e| format!("finalizing diag tar: {e}"))?;
            encoder
                .shutdown()
                .await
                .map_err(|e| format!("flushing zstd encoder: {e}"))?;
            Ok::<(), String>(())
        })
    };

    let mut writer = c.make_writer();
    let copy_result = tokio::io::copy(&mut rx, &mut writer).await;
    let shutdown_result = writer.shutdown().await;
    // The read half must be gone before waiting on the build task: if the
    // copy failed mid-stream (client vanished) the task is still writing,
    // and only a dropped `rx` turns its next write into `BrokenPipe`
    // instead of an indefinite block on the full duplex buffer.
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

#[derive(Serialize)]
struct DiagError {
    collector: String,
    error: String,
}

/// Runs every collector, appending entries to `tar`; failures accumulate.
async fn collect_into_tar<W: AsyncWrite + Unpin + Send + Sync>(
    s: &ServerStateHandle,
    req: &DiagBundleRequest,
    tar: &mut Builder<W>,
) -> Vec<DiagError> {
    let mut errors = Vec::new();
    let fail = |errors: &mut Vec<DiagError>, collector: &str, e: String| {
        tracing::warn!(collector, error = %e, "diag collector failed");
        errors.push(DiagError {
            collector: collector.to_string(),
            error: e,
        });
    };

    let state_dir = s
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .as_std_path()
        .to_path_buf();

    if let Err(e) = meta(s, tar).await {
        fail(&mut errors, "meta", e);
    }
    if let Err(e) = logs(&state_dir, req, tar).await {
        fail(&mut errors, "logs", e);
    }
    if req.include_state_listing {
        // Up to 100k synchronous fs ops — keep them off the RPC-serving
        // runtime, matching the spawn_blocking treatment procs() already uses.
        let listing_dir = state_dir.clone();
        match tokio::task::spawn_blocking(move || {
            diagnostics::listing::listing_text(&listing_dir, LISTING_MAX_ENTRIES)
        })
        .await
        {
            Ok(listing) => {
                if let Err(e) = append_bytes(tar, "state-listing.txt", listing.as_bytes()).await {
                    fail(&mut errors, "state-listing", e.to_string());
                }
            }
            Err(e) => fail(
                &mut errors,
                "state-listing",
                format!("listing task panicked: {e}"),
            ),
        }
    }
    if let Err(e) = sessions(&state_dir, tar).await {
        fail(&mut errors, "sessions", e);
    }
    if let Err(e) = procs(tar).await {
        fail(&mut errors, "proc", e);
    }
    if let Err(e) = net_tables(tar).await {
        fail(&mut errors, "net", e);
    }
    if s.in_microvm().await
        && let Err(e) = gvproxy_probe(tar).await
    {
        fail(&mut errors, "net.gvproxy", e);
    }
    if let Err(e) = disk(&state_dir, tar).await {
        fail(&mut errors, "disk", e);
    }
    errors
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

async fn meta<W: AsyncWrite + Unpin + Send + Sync>(
    s: &ServerStateHandle,
    tar: &mut Builder<W>,
) -> Result<(), String> {
    let uptime = tokio::fs::read_to_string("/proc/uptime").await.ok();
    let info = Meta {
        version: env!("CARGO_PKG_VERSION"),
        long_version: env!("LONG_VERSION"),
        stdlib_version: stdlib::VERSION,
        pid: std::process::id(),
        uptime_secs: uptime.and_then(|s| s.split_whitespace().next()?.parse().ok()),
        in_microvm: s.in_microvm().await,
        state_volume_mounted: s.state_volume_mounted().await,
        state_dir: s.minimal_state_dir().await.to_string(),
    };
    let json = serde_json::to_vec_pretty(&info).map_err(|e| format!("serializing meta: {e}"))?;
    append_bytes(tar, "meta.json", &json)
        .await
        .map_err(|e| e.to_string())
}

async fn logs<W: AsyncWrite + Unpin + Send + Sync>(
    state_dir: &std::path::Path,
    req: &DiagBundleRequest,
    tar: &mut Builder<W>,
) -> Result<(), String> {
    let cap = if req.log_tail_bytes == 0 {
        DEFAULT_LOG_TAIL_BYTES
    } else {
        req.log_tail_bytes
    };
    let Ok(mut entries) = tokio::fs::read_dir(state_dir.join("logs")).await else {
        return Ok(()); // never ran detached — no log dir
    };
    // Only this daemon's own rotated logs: the state dir can be shared with
    // minvmd (native installs), whose files belong to the host-side
    // collector, not the daemon's self-view.
    let mut files = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        // Regular files only: the in-VM daemon reads a volume guest tasks can
        // write, so a symlink named `minimald.log.*` must not steer an
        // unrelated target into the bundle. dirent file_type does not follow.
        if !entry.file_type().await.is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("minimald.log"))
        {
            files.push(path);
        }
    }
    // Rolling filenames embed the date, so reverse lexical = newest first.
    files.sort();
    files.reverse();
    for path in files.into_iter().take(LOG_FILES_MAX) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let contents = read_tail(&path, cap)
            .await
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        append_bytes(tar, &format!("logs/{name}"), &contents)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn sessions<W: AsyncWrite + Unpin + Send + Sync>(
    state_dir: &std::path::Path,
    tar: &mut Builder<W>,
) -> Result<(), String> {
    let sessions_dir = state_dir.join("sessions");
    match tokio::fs::read(sessions_dir.join("index.json")).await {
        Ok(bytes) => append_bytes(tar, "sessions/index.json", &bytes)
            .await
            .map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("reading sessions/index.json: {e}")),
    }
    let Ok(mut entries) = tokio::fs::read_dir(&sessions_dir).await else {
        return Ok(());
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let short = entry.file_name().to_string_lossy().to_string();
        // An absent file is always explainable (the module contract): a
        // genuinely-missing record is silent, but a read failure or an
        // unparseable-and-withheld record leaves a note in its place rather
        // than vanishing.
        let raw = match tokio::fs::read(entry.path().join("record.json")).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                let note = format!("withheld: unreadable: {e}");
                append_bytes(
                    tar,
                    &format!("sessions/{short}/record.error.txt"),
                    note.as_bytes(),
                )
                .await
                .map_err(|e| e.to_string())?;
                continue;
            }
        };
        // Records can hold user env-var values (loadout vars); mask
        // secret-shaped content before it leaves the machine.
        match serde_json::from_slice::<serde_json::Value>(&raw) {
            Ok(mut value) => {
                diagnostics::redact::redact_json(&mut value);
                let json = serde_json::to_vec_pretty(&value)
                    .map_err(|e| format!("serializing record: {e}"))?;
                append_bytes(
                    tar,
                    &format!("sessions/{short}/record.json.redacted"),
                    &json,
                )
                .await
                .map_err(|e| e.to_string())?;
            }
            Err(e) => {
                // Withheld: can't redact safely. Record why in its place.
                let note = format!("withheld: does not parse as JSON, cannot redact safely: {e}");
                append_bytes(
                    tar,
                    &format!("sessions/{short}/record.error.txt"),
                    note.as_bytes(),
                )
                .await
                .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// Full process table from `/proc` — pid, ppid, rss, and command line. The
/// guest rootfs has no `ps`; inside the VM every process is ours anyway. On
/// the (Linux-only) native daemon this stays scoped to the daemon's view.
async fn procs<W: AsyncWrite + Unpin + Send + Sync>(tar: &mut Builder<W>) -> Result<(), String> {
    // Hundreds of synchronous /proc reads on a busy host — keep them off the
    // shared RPC-serving runtime.
    let text = tokio::task::spawn_blocking(proc_table)
        .await
        .map_err(|e| format!("proc scrape task panicked: {e}"))??;
    append_bytes(tar, "proc.txt", text.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

/// argv0 basenames whose full command line is ours to record. Everything
/// else is reported by process name (`comm`) only.
const PROC_MARKERS: &[&str] = &[
    "min",
    "minimal",
    "minimald",
    "minvmd",
    "__krun-vmm",
    "gvproxy",
];

fn proc_table() -> Result<String, String> {
    use std::fmt::Write as _;
    // On a native (non-VM) daemon /proc is the whole host process table, so
    // full argv is captured only for the minimal process family — unrelated
    // processes contribute their `comm` name, never their arguments.
    let mut text = String::from("pid\tppid\tvmrss_kb\tcmd\n");
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("reading /proc: {e}"))?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|raw| String::from_utf8_lossy(&raw).replace('\0', " "))
            .unwrap_or_default();
        let ours = cmdline
            .split_whitespace()
            .next()
            .map(|argv0| argv0.rsplit('/').next().unwrap_or(argv0))
            .is_some_and(|bin| PROC_MARKERS.contains(&bin));
        let cmd = if ours {
            cmdline.trim_end().to_string()
        } else {
            // comm is the process name only (no arguments).
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|c| c.trim_end().to_string())
                .unwrap_or_default()
        };
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let field = |key: &str| {
            status
                .lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("-")
                .to_string()
        };
        let _ = writeln!(
            text,
            "{pid}\t{}\t{}\t{cmd}",
            field("PPid:"),
            field("VmRSS:")
        );
    }
    Ok(text)
}

async fn net_tables<W: AsyncWrite + Unpin + Send + Sync>(
    tar: &mut Builder<W>,
) -> Result<(), String> {
    let interfaces = tokio::fs::read_to_string("/proc/net/dev")
        .await
        .unwrap_or_else(|e| format!("<unreadable: {e}>"));
    append_bytes(tar, "net/interfaces.txt", interfaces.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut listening = String::new();
    for table in ["tcp", "tcp6", "udp", "unix"] {
        let path = format!("/proc/net/{table}");
        listening.push_str(&format!("=== {path} ===\n"));
        match tokio::fs::read_to_string(&path).await {
            Ok(t) => listening.push_str(&t),
            Err(e) => listening.push_str(&format!("<unreadable: {e}>\n")),
        }
    }
    append_bytes(tar, "net/listening.txt", listening.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct GvproxyProbe {
    endpoint: String,
    connect: String,
    http_head: Option<String>,
}

/// Reachability of the gvproxy management endpoint from inside the VM — the
/// single NAT hop every guest egress depends on.
async fn gvproxy_probe<W: AsyncWrite + Unpin + Send + Sync>(
    tar: &mut Builder<W>,
) -> Result<(), String> {
    let (host, port) = GVPROXY_MGMT;
    let endpoint = format!("{host}:{port}");
    let probe = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
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
            let http_head = tokio::time::timeout(std::time::Duration::from_secs(2), http_head)
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
    let json =
        serde_json::to_vec_pretty(&probe).map_err(|e| format!("serializing gvproxy probe: {e}"))?;
    append_bytes(tar, "net/gvproxy.json", &json)
        .await
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct DiskInfo {
    path: String,
    total_bytes: Option<u64>,
    free_bytes: Option<u64>,
}

async fn disk<W: AsyncWrite + Unpin + Send + Sync>(
    state_dir: &std::path::Path,
    tar: &mut Builder<W>,
) -> Result<(), String> {
    #[derive(Serialize)]
    struct Disk {
        filesystems: Vec<DiskInfo>,
        mounts: String,
    }
    let info = Disk {
        filesystems: [state_dir, std::path::Path::new("/")]
            .into_iter()
            .map(|p| {
                let stat = statvfs(p);
                DiskInfo {
                    path: p.display().to_string(),
                    total_bytes: stat.map(|(t, _)| t),
                    free_bytes: stat.map(|(_, f)| f),
                }
            })
            .collect(),
        mounts: tokio::fs::read_to_string("/proc/mounts")
            .await
            .unwrap_or_else(|e| format!("<unreadable: {e}>")),
    };
    let json =
        serde_json::to_vec_pretty(&info).map_err(|e| format!("serializing disk info: {e}"))?;
    append_bytes(tar, "disk.json", &json)
        .await
        .map_err(|e| e.to_string())
}

/// `(total, free-for-unprivileged)` bytes of the filesystem holding `path`.
fn statvfs(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and out-pointer to a zeroed struct.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize as u64;
    Some((stat.f_blocks as u64 * frsize, stat.f_bavail as u64 * frsize))
}

// ── helpers ──────────────────────────────────────────────────────────────────

async fn append_bytes<W: AsyncWrite + Unpin + Send + Sync>(
    tar: &mut Builder<W>,
    path: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    tar.append_data(&mut header, path, bytes)
        .await
        .map_err(|e| std::io::Error::other(format!("adding {path}: {e}")))
}

/// Up to the last `cap` bytes of `path`.
async fn read_tail(path: &std::path::Path, cap: u64) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncSeekExt as _;
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    if len > cap {
        file.seek(std::io::SeekFrom::End(-(cap as i64))).await?;
    }
    let mut contents = Vec::with_capacity(len.min(cap) as usize);
    file.read_to_end(&mut contents).await?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_harness::TestServer;
    use minimald_rpc::DIAG_BUNDLE_SUBSYSTEM;
    use russh::ChannelMsg;
    use std::collections::BTreeMap;

    /// Requests a diag bundle over the real subsystem, returning the
    /// decompressed entries as `path -> contents`.
    async fn fetch_bundle(server: &TestServer) -> BTreeMap<String, Vec<u8>> {
        let mut client = server.connect().await;
        let channel = client.open_subsystem(DIAG_BUNDLE_SUBSYSTEM, &[]).await;

        let body = serde_json::to_vec(&DiagBundleRequest::default()).unwrap();
        channel.data(&body[..]).await.unwrap();
        channel.eof().await.unwrap();

        let mut channel = channel;
        let mut bundle = Vec::new();
        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => bundle.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                _ => {}
            }
        }
        assert!(
            !bundle.is_empty(),
            "no bundle streamed; stderr: {}",
            String::from_utf8_lossy(&stderr)
        );

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&bundle[..]);
        let out = tempfile::TempDir::new().unwrap();
        async_tar::Archive::new(decoder)
            .unpack(out.path().to_path_buf())
            .await
            .unwrap();

        let mut files = BTreeMap::new();
        collect_files(out.path(), out.path(), &mut files);
        files
    }

    fn collect_files(
        base: &std::path::Path,
        dir: &std::path::Path,
        files: &mut BTreeMap<String, Vec<u8>>,
    ) {
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

    #[tokio::test]
    async fn diag_bundle_streams_meta_and_error_report() {
        let server = TestServer::new().await;
        let files = fetch_bundle(&server).await;

        let meta: serde_json::Value = serde_json::from_slice(&files["meta.json"]).unwrap();
        assert_eq!(meta["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(meta["in_microvm"], false);
        assert_eq!(meta["pid"], std::process::id());

        // errors.json is always present (possibly empty) and valid JSON.
        let errors: Vec<serde_json::Value> = serde_json::from_slice(&files["errors.json"]).unwrap();
        assert!(
            errors.is_empty(),
            "healthy test server should collect cleanly, got: {errors:?}"
        );

        assert!(files.contains_key("state-listing.txt"));
        assert!(files.contains_key("proc.txt"));
        assert!(files.contains_key("net/listening.txt"));
        assert!(files.contains_key("disk.json"));
        // Not in a microVM: no gvproxy probe entry.
        assert!(!files.contains_key("net/gvproxy.json"));
    }

    #[tokio::test]
    async fn diag_bundle_logs_exclude_other_daemons_files() {
        let server = TestServer::new().await;
        let state_dir = server.state.minimal_state_dir().await;
        let log_dir = state_dir.as_utf8_path().as_std_path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        // minvmd shares the state dir on native installs; its logs sort
        // after ours lexically and must not crowd out the daemon's own.
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
}
