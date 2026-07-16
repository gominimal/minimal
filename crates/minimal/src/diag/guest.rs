//! Fetching the daemon's own diagnostic bundle for `min bug`.
//!
//! The daemon (native minimald or the in-VM one behind the minvmd bridge)
//! streams a nested tar+zstd archive which is stored raw at
//! `providers/<name>/guest/daemon-diag.tar.zst` — never re-packed, so "what
//! the daemon said" stays exactly distinguishable from "what the host saw".

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use serde::Serialize;

use super::bundle::{BundleWriter, LOG_TAIL_CAP};
use super::manifest::Redaction;
use crate::client::Client;

/// Hard cap on the accepted guest bundle. A wedged vsock or runaway log
/// cannot make `min bug` itself balloon.
pub const GUEST_BUNDLE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Downloads the daemon bundle over `client` and stores it under
/// `providers/<provider>/guest/`. On failure writes `error.txt` there,
/// records a collector error, and falls back to reading the data volume
/// image from the host ([`volume_fallback`]) — `min bug` always produces a
/// bundle, and a dead transport is exactly when the guest's logs matter.
pub async fn collect(
    w: &mut BundleWriter,
    provider: &str,
    provider_dir: &Path,
    client: &mut Client,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let started = std::time::Instant::now();
    let req = minimald_rpc::DiagBundleRequest::default();

    let result = tokio::time::timeout(
        timeout,
        client.download_diag_bundle(&req, GUEST_BUNDLE_MAX_BYTES),
    )
    .await;

    let dest = format!("providers/{provider}/guest/daemon-diag.tar.zst");
    match result {
        Ok(Ok((bytes, truncated))) => {
            // A truncated stream is still collected — the manifest entry's
            // redaction records that only the leading bytes survived.
            let redaction = if truncated {
                Redaction::Truncated
            } else {
                Redaction::None
            };
            w.add_bytes(&dest, &bytes, redaction).await
        }
        Ok(Err(e)) => {
            let msg = format!("guest bundle download failed: {e:#}");
            w.error(format!("guest.{provider}"), &msg, started.elapsed());
            w.add_bytes(
                &format!("providers/{provider}/guest/error.txt"),
                msg.as_bytes(),
                Redaction::None,
            )
            .await?;
            volume_fallback(w, provider, provider_dir).await
        }
        Err(_) => {
            let msg = format!("guest bundle download timed out after {timeout:?}");
            w.error(format!("guest.{provider}"), &msg, started.elapsed());
            w.add_bytes(
                &format!("providers/{provider}/guest/error.txt"),
                msg.as_bytes(),
                Redaction::None,
            )
            .await?;
            volume_fallback(w, provider, provider_dir).await
        }
    }
}

#[derive(Serialize)]
struct VolumeMeta {
    path: String,
    exists: bool,
    bytes: Option<u64>,
    mtime_unix: Option<u64>,
}

/// Host-side fallback when the daemon's own bundle couldn't be fetched: the
/// data volume is plain ext4 and safe to read read-only while the VM runs.
/// Records the image's vital signs (its mtime alone dates a stall) and
/// best-effort harvests `/logs` from it via `debugfs -c` when e2fsprogs is
/// installed; otherwise leaves a manifest hint for offline extraction.
pub async fn volume_fallback(
    w: &mut BundleWriter,
    provider: &str,
    provider_dir: &Path,
) -> Result<(), anyhow::Error> {
    let image = provider_dir.join("data-vol.raw");
    let meta = tokio::fs::metadata(&image).await.ok();
    let info = VolumeMeta {
        path: image.display().to_string(),
        exists: meta.is_some(),
        bytes: meta.as_ref().map(|m| m.len()),
        mtime_unix: meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    };
    let json = serde_json::to_vec_pretty(&info).context("serializing volume meta")?;
    w.add_bytes(
        &format!("providers/{provider}/guest/volume-meta.json"),
        &json,
        Redaction::None,
    )
    .await?;
    if meta.is_none() {
        return Ok(());
    }

    let dest_dir = format!("providers/{provider}/guest/volume-logs");
    let hint = format!(
        "harvest offline with: debugfs -c -R 'rdump /logs .' {}",
        image.display()
    );
    let tmp = tempfile::TempDir::new().context("tempdir for volume harvest")?;
    let rdump = format!("rdump /logs {}", tmp.path().display());
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("debugfs")
            .args(["-c", "-R", &rdump])
            .arg(&image)
            .output(),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            let mut added = 0usize;
            if let Ok(mut entries) = tokio::fs::read_dir(tmp.path().join("logs")).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if !entry.file_type().await.is_ok_and(|t| t.is_file()) {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy().to_string();
                    let dest = format!("{dest_dir}/{name}");
                    if let Err(e) = w.add_file_tail(&dest, &entry.path(), LOG_TAIL_CAP).await {
                        w.skip(&dest, format!("unreadable: {e}"));
                    } else {
                        added += 1;
                    }
                }
            }
            if added == 0 {
                let first_err = String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("no debugfs output")
                    .to_string();
                w.skip(
                    &dest_dir,
                    format!("debugfs harvested nothing ({first_err}); {hint}"),
                );
            }
        }
        Ok(Err(e)) => w.skip(&dest_dir, format!("debugfs unavailable ({e}); {hint}")),
        Err(_) => w.skip(&dest_dir, format!("debugfs timed out after 10s; {hint}")),
    }
    Ok(())
}

/// Records why guest collection didn't run (no daemon, `--no-guest`).
pub async fn record_skipped(
    w: &mut BundleWriter,
    provider: &str,
    reason: &str,
) -> Result<(), anyhow::Error> {
    w.add_bytes(
        &format!("providers/{provider}/guest/error.txt"),
        reason.as_bytes(),
        Redaction::None,
    )
    .await
}
