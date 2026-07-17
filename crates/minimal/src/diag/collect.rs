//! Host-side collectors for the `min bug` diagnostic bundle.
//!
//! Each collector is independent: it reads what it can, adds entries to the
//! [`BundleWriter`], and returns an error only for genuinely unexpected
//! failures (an absent file is data, not an error). The orchestrator records
//! collector errors in the manifest and moves on.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::Context as _;
use serde::Serialize;

use super::redact::{is_env_value_allowlisted, redact_toml};
use diagnostics::bundle::{BundleWriter, LOG_TAIL_CAP};
use diagnostics::manifest::Redaction;

/// Cap on entries in a recursive state-dir listing; a runaway tree (huge
/// session workspaces) is truncated with a marker line, not walked forever.
const LISTING_MAX_ENTRIES: usize = 100_000;

/// Everything the host collectors need, resolved once so collection is a
/// pure function of these paths plus the filesystem.
pub struct DiagPaths {
    /// `<config>/minimal`.
    pub config: PathBuf,
    /// `<state>/minimal` (or the `--minimal-dir` override).
    pub state: PathBuf,
    /// `<cache>/minimal`.
    pub cache: PathBuf,
    /// Where `minimal mesh join` writes its enrolment file.
    pub mesh_enrolment: PathBuf,
    /// The invoking directory (disk-full there breaks the bundle write).
    pub cwd: PathBuf,
}

// ── host/system.json ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SystemInfo {
    os: &'static str,
    arch: &'static str,
    kernel: Option<String>,
    hostname: Option<String>,
    ncpu: Option<usize>,
    euid: u32,
    #[cfg(target_os = "linux")]
    kvm: KvmInfo,
    disks: Vec<DiskInfo>,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct KvmInfo {
    exists: bool,
    /// `ok` / `enoent` / `eacces` / other errno string — ENOENT means the
    /// module isn't loaded, EACCES means the user isn't in the kvm group.
    open_result: String,
    mode: Option<String>,
    owner_gid: Option<u32>,
    user_in_kvm_group: Option<bool>,
}

#[derive(Serialize)]
struct DiskInfo {
    path: String,
    total_bytes: Option<u64>,
    free_bytes: Option<u64>,
}

pub async fn system(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    let kernel = command_line_output("uname", &["-srvm"]).await;
    let hostname = command_line_output("uname", &["-n"]).await;
    let info = SystemInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kernel,
        hostname,
        ncpu: std::thread::available_parallelism().map(usize::from).ok(),
        // SAFETY: geteuid has no failure modes or preconditions.
        euid: unsafe { libc::geteuid() },
        #[cfg(target_os = "linux")]
        kvm: kvm_info(),
        disks: [&paths.state, &paths.cache, &paths.cwd]
            .into_iter()
            .map(|p| disk_info(p))
            .collect(),
    };
    let json = serde_json::to_vec_pretty(&info).context("serializing system info")?;
    w.add_bytes("host/system.json", &json, Redaction::None)
        .await
}

/// First line of `cmd args` stdout, or `None` if it can't run. 5s timeout.
async fn command_line_output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(cmd)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    })
}

#[cfg(target_os = "linux")]
fn kvm_info() -> KvmInfo {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata("/dev/kvm").ok();
    let open_result = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => "ok".to_string(),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => "enoent".to_string(),
            std::io::ErrorKind::PermissionDenied => "eacces".to_string(),
            _ => e.to_string(),
        },
    };
    KvmInfo {
        exists: meta.is_some(),
        open_result,
        mode: meta.as_ref().map(|m| format!("{:o}", m.mode())),
        owner_gid: meta.as_ref().map(|m| m.gid()),
        user_in_kvm_group: user_in_group("kvm"),
    }
}

/// Whether the current user's supplementary groups include `name`.
/// `None` when the group doesn't exist or the group list can't be read.
#[cfg(target_os = "linux")]
fn user_in_group(name: &str) -> Option<bool> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam reads a NUL-terminated string; the returned struct is
    // a static buffer only read before any other getgr* call in this thread.
    let grp = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if grp.is_null() {
        return None;
    }
    // SAFETY: non-null getgrnam result points to a valid `group`.
    let target_gid = unsafe { (*grp).gr_gid };

    // SAFETY: first call sizes the buffer, second fills it.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        return None;
    }
    let mut gids = vec![0 as libc::gid_t; n as usize];
    // SAFETY: buffer is exactly the size getgroups asked for.
    let n = unsafe { libc::getgroups(n, gids.as_mut_ptr()) };
    if n < 0 {
        return None;
    }
    gids.truncate(n as usize);
    // SAFETY: getegid has no failure modes.
    let egid = unsafe { libc::getegid() };
    Some(gids.contains(&target_gid) || egid == target_gid)
}

fn disk_info(path: &Path) -> DiskInfo {
    let stat = statvfs(path);
    DiskInfo {
        path: path.display().to_string(),
        total_bytes: stat.map(|(total, _)| total),
        free_bytes: stat.map(|(_, free)| free),
    }
}

/// `(total, free-for-unprivileged)` bytes of the filesystem holding `path`,
/// or `None` when the path doesn't exist.
fn statvfs(path: &Path) -> Option<(u64, u64)> {
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

// ── host/env.json ────────────────────────────────────────────────────────────

pub async fn env(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    // vars_os, not vars: the latter panics on a non-UTF-8 name or value, and
    // a panic here would unwind past the collect_step! guard and abort the
    // whole run with an unfinalized archive.
    let env: std::collections::BTreeMap<String, String> = std::env::vars_os()
        .map(|(name_os, value_os)| {
            let name = name_os.to_string_lossy().into_owned();
            let shown = if is_env_value_allowlisted(&name) {
                value_os.to_string_lossy().into_owned()
            } else {
                format!("<redacted:len={}>", value_os.as_encoded_bytes().len())
            };
            (name, shown)
        })
        .collect();
    let json = serde_json::to_vec_pretty(&env).context("serializing env")?;
    w.add_bytes("host/env.json", &json, Redaction::Keys).await
}

// ── config/ ──────────────────────────────────────────────────────────────────

pub async fn config(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    add_redacted_toml(
        w,
        &paths.config.join("config.toml"),
        "config/config.toml.redacted",
    )
    .await;
    add_redacted_toml(
        w,
        &paths.config.join("user_policy.toml"),
        "config/user_policy.toml.redacted",
    )
    .await;

    if let Ok(mut entries) = tokio::fs::read_dir(paths.config.join("loadouts")).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "toml")
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
            {
                add_redacted_toml(w, &path, &format!("config/loadouts/{name}.redacted")).await;
            }
        }
    }

    // mTLS material: cert/CA metadata only, private key never touched.
    w.skip(
        "config/client.key",
        "private key material — never collected",
    );
    let certs: std::collections::BTreeMap<&str, Option<FileMeta>> = [
        (
            "client.pem",
            file_meta(&paths.config.join("client.pem")).await,
        ),
        ("ca.pem", file_meta(&paths.config.join("ca.pem")).await),
    ]
    .into_iter()
    .collect();
    let json = serde_json::to_vec_pretty(&certs).context("serializing cert metadata")?;
    w.add_bytes("config/client-cert.json", &json, Redaction::ListingOnly)
        .await?;

    // Mesh enrolment holds only a host:port endpoint.
    match tokio::fs::read(&paths.mesh_enrolment).await {
        Ok(bytes) => {
            w.add_bytes("config/mesh-enrolment", &bytes, Redaction::None)
                .await?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => w.skip("config/mesh-enrolment", format!("unreadable: {e}")),
    }
    Ok(())
}

/// Adds a TOML file with values redacted; a missing file is silently fine,
/// an unparseable or unreadable one is withheld with a manifest note.
async fn add_redacted_toml(w: &mut BundleWriter, src: &Path, dest: &str) {
    let content = match tokio::fs::read_to_string(src).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            w.skip(dest, format!("unreadable: {e}"));
            return;
        }
    };
    match redact_toml(&content) {
        Ok(redacted) => {
            if let Err(e) = w
                .add_bytes(dest, redacted.as_bytes(), Redaction::Keys)
                .await
            {
                w.skip(dest, format!("bundling failed: {e}"));
            }
        }
        Err(e) => w.skip(
            dest,
            format!("withheld: does not parse as TOML, cannot redact safely: {e}"),
        ),
    }
}

#[derive(Serialize)]
struct FileMeta {
    bytes: u64,
    mtime_unix: Option<u64>,
}

async fn file_meta(path: &Path) -> Option<FileMeta> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    Some(FileMeta {
        bytes: meta.len(),
        mtime_unix: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    })
}

// ── state/ ───────────────────────────────────────────────────────────────────

pub async fn state(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    // Recursive listing: names, sizes, and metadata only — session workspace
    // *contents* stay on the user's machine.
    let listing = diagnostics::listing::listing_text(&paths.state, LISTING_MAX_ENTRIES);
    w.add_bytes(
        "state/listing.txt",
        listing.as_bytes(),
        Redaction::ListingOnly,
    )
    .await?;

    let sessions_dir = paths.state.join("sessions");
    match tokio::fs::read(sessions_dir.join("index.json")).await {
        Ok(bytes) => {
            w.add_bytes("state/sessions/index.json", &bytes, Redaction::None)
                .await?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => w.skip("state/sessions/index.json", format!("unreadable: {e}")),
    }

    // Per-session records, secret-shaped values masked.
    if let Ok(mut entries) = tokio::fs::read_dir(&sessions_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let short = entry.file_name().to_string_lossy().to_string();
            let record_path = entry.path().join("record.json");
            let dest = format!("state/sessions/{short}/record.json.redacted");
            let content = match tokio::fs::read(&record_path).await {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    w.skip(&dest, format!("unreadable: {e}"));
                    continue;
                }
            };
            match serde_json::from_slice::<serde_json::Value>(&content) {
                Ok(mut value) => {
                    diagnostics::redact::redact_json(&mut value);
                    let json = serde_json::to_vec_pretty(&value).context("serializing record")?;
                    w.add_bytes(&dest, &json, Redaction::Keys).await?;
                }
                Err(e) => w.skip(
                    &dest,
                    format!("withheld: does not parse as JSON, cannot redact safely: {e}"),
                ),
            }
        }
    }
    Ok(())
}

// ── logs/ ────────────────────────────────────────────────────────────────────

/// How many rotated files per log prefix make it into the bundle.
const LOG_FILES_PER_PREFIX: usize = 5;

pub async fn logs(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    let log_dir = paths.state.join("logs");
    let Ok(mut entries) = tokio::fs::read_dir(&log_dir).await else {
        return Ok(()); // no log dir at all — nothing ever detached
    };
    let mut all: Vec<PathBuf> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        all.push(entry.path());
    }
    for prefix in ["minimald.log", "minvmd.log"] {
        // Rolling filenames embed the date (`minimald.log.2026-07-15`), so a
        // reverse lexical sort is newest-first.
        let mut files: Vec<&PathBuf> = all
            .iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix))
            })
            .collect();
        files.sort();
        files.reverse();
        for path in files.into_iter().take(LOG_FILES_PER_PREFIX) {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let dest = format!("logs/{name}");
            if let Err(e) = w.add_file_tail(&dest, path, LOG_TAIL_CAP).await {
                w.skip(&dest, format!("unreadable: {e}"));
            }
        }
    }
    Ok(())
}

// ── providers/local-<n>/ (files only; socket probe lives in net.rs) ─────────

/// Provider instance dirs under `<state>/providers`, sorted. Empty when the
/// providers dir doesn't exist (nothing was ever spawned).
pub async fn provider_dirs(state: &Path) -> Vec<(String, PathBuf)> {
    let Ok(mut entries) = tokio::fs::read_dir(state.join("providers")).await else {
        return Vec::new();
    };
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.starts_with("local-") {
            dirs.push((name, entry.path()));
        }
    }
    dirs.sort();
    dirs
}

#[derive(Serialize)]
struct ProviderStatus {
    /// Raw lifecycle from `minvmd.toml` — never repaired/written back.
    state: Option<toml::Table>,
    state_read_error: Option<String>,
    /// Live minvmd (or its VMM child) holds `minvmd.lock`.
    minvmd_alive: Option<bool>,
    /// Live native minimald holds `minimald.lock`.
    minimald_alive: Option<bool>,
}

pub async fn provider_files(
    w: &mut BundleWriter,
    name: &str,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    // Shallow listing of the provider dir: which sockets/locks/keys exist.
    let listing = diagnostics::listing::listing_text(dir, LISTING_MAX_ENTRIES);
    w.add_bytes(
        &format!("providers/{name}/dir-listing.txt"),
        listing.as_bytes(),
        Redaction::ListingOnly,
    )
    .await?;

    w.skip(
        format!("providers/{name}/ssh_host_ed25519_key"),
        "private key material — never collected",
    );

    // Lifecycle state, verbatim (nothing sensitive: enum + pid + timestamp).
    match tokio::fs::read(dir.join("minvmd.toml")).await {
        Ok(bytes) => {
            w.add_bytes(
                &format!("providers/{name}/minvmd.toml"),
                &bytes,
                Redaction::None,
            )
            .await?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => w.skip(
            format!("providers/{name}/minvmd.toml"),
            format!("unreadable: {e}"),
        ),
    }

    // run.log: the detached supervisor's stderr redirect (panics, the final
    // error print of a failed boot). boot.log: the VMM's hvc0 console
    // capture — kernel prints and the guest pid-1's stdout, the only
    // evidence when the guest wedges before (or its transport dies after)
    // the daemon is reachable (#788).
    for log_name in ["run.log", "boot.log"] {
        let log_path = dir.join(log_name);
        if tokio::fs::try_exists(&log_path).await.unwrap_or(false) {
            let dest = format!("providers/{name}/{log_name}");
            if let Err(e) = w.add_file_tail(&dest, &log_path, LOG_TAIL_CAP).await {
                w.skip(&dest, format!("unreadable: {e}"));
            }
        }
    }

    // Non-mutating status: raw state + advisory-lock liveness probes.
    // Deliberately NOT `StateDir::effective_state()`, which repairs stale
    // state by writing `Stopped` back — a diagnostic must never mutate.
    let state_dir = minvmd::state::StateDir::new(dir.to_path_buf());
    let status = match &state_dir {
        Ok(sd) => {
            let (state, state_read_error) = match tokio::fs::read_to_string(sd.state_path()).await {
                Ok(s) => match s.parse::<toml::Table>() {
                    Ok(v) => (Some(v), None),
                    Err(e) => (None, Some(e.to_string())),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
                Err(e) => (None, Some(e.to_string())),
            };
            ProviderStatus {
                state,
                state_read_error,
                minvmd_alive: sd.daemon_alive().ok(),
                minimald_alive: sd.minimald_alive().ok(),
            }
        }
        Err(e) => ProviderStatus {
            state: None,
            state_read_error: Some(e.to_string()),
            minvmd_alive: None,
            minimald_alive: None,
        },
    };
    let json = serde_json::to_vec_pretty(&status).context("serializing provider status")?;
    w.add_bytes(
        &format!("providers/{name}/status.json"),
        &json,
        Redaction::None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provider_dirs_finds_only_local_instances() {
        let tmp = tempfile::TempDir::new().unwrap();
        let providers = tmp.path().join("providers");
        std::fs::create_dir_all(providers.join("local-0")).unwrap();
        std::fs::create_dir_all(providers.join("local-2")).unwrap();
        std::fs::create_dir_all(providers.join("remote-x")).unwrap();
        std::fs::write(providers.join("stray-file"), "").unwrap();

        let dirs = provider_dirs(tmp.path()).await;
        let names: Vec<&str> = dirs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["local-0", "local-2"]);
    }

    #[tokio::test]
    async fn provider_dirs_empty_when_never_spawned() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(provider_dirs(tmp.path()).await.is_empty());
    }
}
