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

use super::redact::is_env_value_allowlisted;
use diagnostics::redact::{masked_process_env, redact_toml};
use diagnostics::{BundleWriter, LOG_TAIL_CAP, Redaction, open_regular_nofollow};

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
    /// Where `min mesh join` writes its enrolment file.
    pub mesh_enrolment: PathBuf,
    /// The invoking directory (disk-full there breaks the bundle write).
    pub cwd: PathBuf,
}

// ── host/system.json ─────────────────────────────────────────────────────────

pub async fn system(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    // Which filesystems matter is this binary's policy: the state dir, the
    // cache dir, and the invoking directory the archive is written into.
    let info = diagnostics::system_info(&[&paths.state, &paths.cache, &paths.cwd]).await;
    let json = serde_json::to_vec_pretty(&info).context("serializing system info")?;
    w.add_bytes("host/system.json", &json, Redaction::None)
        .await
}

// ── host/env.json ────────────────────────────────────────────────────────────

pub async fn env(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let env = masked_process_env(is_env_value_allowlisted);
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

    match tokio::fs::read_dir(paths.config.join("loadouts")).await {
        Ok(mut entries) => loop {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "toml")
                        && let Some(name) = path.file_name().and_then(|n| n.to_str())
                    {
                        add_redacted_toml(w, &path, &format!("config/loadouts/{name}.redacted"))
                            .await;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    w.skip("config/loadouts/", format!("listing interrupted: {e}"));
                    break;
                }
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => w.skip("config/loadouts/", format!("unreadable: {e}")),
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

    // Mesh enrolment holds only a host:port endpoint. No-follow like every
    // other content read: it ships verbatim, so a symlink here would
    // exfiltrate an arbitrary file byte-for-byte.
    match read_string_nofollow(&paths.mesh_enrolment).await {
        Ok(content) => {
            w.add_bytes("config/mesh-enrolment", content.as_bytes(), Redaction::None)
                .await?
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => w.skip("config/mesh-enrolment", format!("unreadable: {e:#}")),
    }
    Ok(())
}

/// Adds a TOML file with values redacted; a missing file is silently fine,
/// an unparseable, unreadable, or symlinked one is withheld with a manifest
/// note (the no-follow discipline covers content reads, not just log tails —
/// a symlinked "config" file must not steer unrelated data into the bundle).
async fn add_redacted_toml(w: &mut BundleWriter, src: &Path, dest: &str) {
    let content = match read_string_nofollow(src).await {
        Ok(c) => c,
        Err(e) if is_not_found(&e) => return,
        Err(e) => {
            w.skip(dest, format!("unreadable: {e:#}"));
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

/// Reads a regular file to a string without following symlinks.
async fn read_string_nofollow(src: &Path) -> Result<String, anyhow::Error> {
    use tokio::io::AsyncReadExt as _;
    let (mut file, _) = open_regular_nofollow(src).await?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .await
        .with_context(|| format!("reading {}", src.display()))?;
    Ok(content)
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
    // *contents* stay on the user's machine. The walk is synchronous, so it
    // runs on a blocking thread: a wedged filesystem must strand that
    // thread, not the worker whose collect_step! timeout is the failsafe.
    let state_dir = paths.state.clone();
    let listing =
        tokio::task::spawn_blocking(move || diagnostics::listing(&state_dir, LISTING_MAX_ENTRIES))
            .await
            .context("listing worker")?
            .context("listing state dir")?;
    w.add_bytes(
        "state/listing.txt",
        listing.text.as_bytes(),
        Redaction::ListingOnly,
    )
    .await
}

// ── logs/ ────────────────────────────────────────────────────────────────────

/// How many rotated files per log prefix make it into the bundle.
const LOG_FILES_PER_PREFIX: usize = 5;

pub async fn logs(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    let log_dir = paths.state.join("logs");
    // Absence and inaccessibility are different facts: "no log directory"
    // may only be claimed on a real NotFound, never on EACCES or I/O errors.
    match tokio::fs::metadata(&log_dir).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No log dir at all — nothing ever detached. Absence is data.
            w.skip("logs/", "no log directory — no daemon has ever logged here");
        }
        Err(e) => w.skip("logs/", format!("unreadable: {e}")),
        Ok(_) => {
            for prefix in ["minimald.log", "minvmd.log"] {
                let files =
                    diagnostics::newest_rotated(&log_dir, prefix, LOG_FILES_PER_PREFIX).await;
                if files.is_empty() {
                    w.skip(format!("logs/{prefix}*"), "no files with this prefix");
                    continue;
                }
                for path in files {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let dest = format!("logs/{name}");
                    if let Err(e) = w.add_file_tail(&dest, &path, LOG_TAIL_CAP).await {
                        w.skip(&dest, format!("unreadable: {e}"));
                    }
                }
            }
        }
    }

    // Provider-scoped logs. run.log: the detached supervisor's stderr
    // redirect (panics, the final error print of a failed boot). boot.log:
    // the VMM's hvc0 console capture — kernel prints and the guest pid-1's
    // stdout, the only evidence when the guest wedges before (or its
    // transport dies after) the daemon is reachable.
    for (name, dir) in provider_dirs(&paths.state).await? {
        for log_name in ["run.log", "boot.log"] {
            let dest = format!("providers/{name}/{log_name}");
            match w
                .add_file_tail(&dest, &dir.join(log_name), LOG_TAIL_CAP)
                .await
            {
                Ok(()) => {}
                Err(e) if is_not_found(&e) => w.skip(&dest, "absent"),
                Err(e) => w.skip(&dest, format!("unreadable: {e}")),
            }
        }
    }
    Ok(())
}

/// True when an `add_file_tail` failure was a plain missing file.
fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::NotFound)
}

// ── providers/local-<n>/ discovery ───────────────────────────────────────────

/// Provider instance dirs under `<state>/providers`, sorted. Empty when the
/// providers dir doesn't exist (nothing was ever spawned); any other
/// filesystem error is an `Err` — "no daemon was ever spawned here" must
/// never be claimed on the strength of an EACCES.
pub async fn provider_dirs(state: &Path) -> Result<Vec<(String, PathBuf)>, std::io::Error> {
    let mut entries = match tokio::fs::read_dir(state.join("providers")).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
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
    Ok(dirs)
}

/// Non-log per-provider evidence: what the instance dir holds, its raw
/// lifecycle state, and whether anything is still alive behind it (R7.6).
///
/// `run.log`/`boot.log` are deliberately *not* collected here — [`logs`]
/// already tail-caps them for every discovered provider, and a second copy
/// would be a duplicate archive entry.
pub async fn provider_files(
    w: &mut BundleWriter,
    name: &str,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    // Shallow inventory of the instance dir: which sockets, locks, keys and
    // images exist. Metadata only — the walk is synchronous, so it runs on a
    // blocking thread like every other listing.
    let listing_dir = dir.to_path_buf();
    let listing = tokio::task::spawn_blocking(move || {
        diagnostics::listing(&listing_dir, LISTING_MAX_ENTRIES)
    })
    .await
    .context("provider listing worker")?;
    let dest = format!("providers/{name}/dir-listing.txt");
    match listing {
        Ok(listing) => {
            w.add_bytes(&dest, listing.text.as_bytes(), Redaction::ListingOnly)
                .await?
        }
        Err(e) => w.skip(&dest, format!("unreadable: {e:#}")),
    }

    w.skip(
        format!("providers/{name}/ssh_host_ed25519_key"),
        "private key material — never collected",
    );

    // Lifecycle state, verbatim (nothing sensitive: enum + pid + timestamp).
    //
    // Read through the same `O_NOFOLLOW` discipline as every other bundled
    // file: `tokio::fs::read` would follow a symlink planted here and copy an
    // unrelated readable host file into a bundle meant for sharing.
    let dest = format!("providers/{name}/minvmd.toml");
    match diagnostics::open_regular_nofollow(&dir.join("minvmd.toml")).await {
        Ok((mut file, _)) => {
            let mut bytes = Vec::new();
            match tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes).await {
                Ok(_) => w.add_bytes(&dest, &bytes, Redaction::None).await?,
                Err(e) => w.skip(&dest, format!("unreadable: {e}")),
            }
        }
        Err(e) => match e.downcast_ref::<std::io::Error>() {
            Some(io) if io.kind() == std::io::ErrorKind::NotFound => {}
            _ => w.skip(&dest, format!("unreadable: {e:#}")),
        },
    }

    let status_dir = dir.to_path_buf();
    let status = tokio::task::spawn_blocking(move || provider_status(&status_dir))
        .await
        .context("provider status worker")?;
    let json = serde_json::to_vec_pretty(&status).context("serializing provider status")?;
    w.add_bytes(
        &format!("providers/{name}/status.json"),
        &json,
        Redaction::None,
    )
    .await
}

#[derive(Serialize)]
struct ProviderStatus {
    /// Raw lifecycle from `minvmd.toml` — never repaired/written back.
    state: Option<toml::Table>,
    state_read_error: Option<String>,
    /// A live minvmd (or its VMM child) holds `minvmd.lock`.
    minvmd_alive: Option<bool>,
    /// A live native minimald holds `minimald.lock`.
    minimald_alive: Option<bool>,
}

/// Reads the provider's lifecycle state and probes the advisory locks.
///
/// Deliberately *not* `StateDir::effective_state()`, which repairs stale state
/// by writing `Stopped` back — a diagnostic must never mutate what it reads.
/// Synchronous (file locks and `std::fs`); callers run it on a blocking thread.
fn provider_status(dir: &Path) -> ProviderStatus {
    // `StateDir::new` runs `create_dir_all`, so probing a provider whose
    // directory had been deleted would recreate it — leaving ghost state
    // behind and making this collector a mutation, which the paragraph above
    // says it must never be.
    let state_dir = minvmd::state::StateDir::open_existing(dir.to_path_buf());
    let (state, state_read_error) = match std::fs::read_to_string(state_dir.state_path()) {
        Ok(s) => match s.parse::<toml::Table>() {
            Ok(table) => (Some(table), None),
            Err(e) => (None, Some(e.to_string())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => (None, Some(e.to_string())),
    };
    ProviderStatus {
        state,
        state_read_error,
        minvmd_alive: state_dir.daemon_alive().ok(),
        minimald_alive: state_dir.minimald_alive().ok(),
    }
}
