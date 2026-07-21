//! Fetching the daemon's own diagnostic bundle for `min bug`.
//!
//! The daemon (native minimald or the in-VM one behind the minvmd bridge)
//! streams a nested tar+zstd archive which is stored **raw** at
//! `providers/<name>/guest/daemon-diag.tar.zst` — never re-packed, so "what
//! the daemon said" stays exactly distinguishable from "what the host saw".
//!
//! When the daemon cannot be reached at all — the case where its logs matter
//! most — the host falls back to the data volume image, which is plain ext4
//! and safe to read read-only while the VM runs.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::Serialize;
use tokio::io::AsyncReadExt as _;
use tokio_stream::StreamExt as _;

use crate::client::Client;
use diagnostics::{BundleWriter, LOG_TAIL_CAP, Redaction};

/// Hard cap on the accepted guest bundle. A wedged vsock or a runaway log
/// cannot make `min bug` itself balloon.
pub const GUEST_BUNDLE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Deadline for the `debugfs` harvest of the volume image. It is scanning a
/// possibly-large image on a possibly-sick disk; the fallback is best-effort.
const DEBUGFS_TIMEOUT: Duration = Duration::from_secs(10);

// ── R7.3: bounded verification of the nested bundle ──────────────────────────
//
// A malicious or corrupt daemon must not be able to make `min bug` decode an
// unbounded amount from the blob it hands us. The blob is stored raw either
// way (R7.3); verification only decides whether the manifest records it as
// trustworthy. The decode is *streaming into a sink* — the decompressed bytes
// are counted and dropped, never materialized — and stops the instant a cap
// trips, so even a pathological input costs only bounded, transient work.
//
// Three independent caps, matching R7.3:
//   * absolute decompressed ceiling — the real memory/CPU guard;
//   * entry count — the header-dimension bomb (millions of empty members),
//     which the byte budget deliberately does not charge for;
//   * `manifest.json` present — a well-formed daemon bundle always ends with
//     one, so its absence means the stream is not what it claims to be.
//
// DEVIATION FROM SPEC — the expansion *ratio*. R7.3 writes "4× the compressed
// size". Measured against a representative bundle, real diagnostic content
// (proc tables, JSON, logs — all highly compressible text) expands ~15×, so a
// literal 4× budget rejects every legitimate nested bundle. The ratio still
// earns its keep for genuinely large blobs, but below `NESTED_MIN_BUDGET` it is
// meaningless (a few hundred KB decoded to check is free), so the budget is
// `clamp(4×compressed, MIN_BUDGET, MAX_DECOMPRESSED)`. The two hard caps the
// bomb guard actually rests on — the 1 GiB ceiling and the 10k-entry cap — are
// exactly as specified.

/// Entry-count ceiling for the nested bundle (R7.3). Bounds the header
/// dimension of a bomb, which the byte budget does not charge for.
const NESTED_MAX_ENTRIES: usize = 10_000;
/// Decompressed content is allowed this multiple of the compressed size.
const NESTED_EXPANSION_RATIO: u64 = 4;
/// Floor under the ratio budget: below this, the ratio is not a meaningful
/// bomb signal and decoding this much to find out is free. See the deviation
/// note above.
const NESTED_MIN_BUDGET: u64 = 64 * 1024 * 1024;
/// Absolute ceiling on decompressed content, whatever the ratio allows (R7.3).
const NESTED_MAX_DECOMPRESSED: u64 = 1024 * 1024 * 1024;

/// Downloads the daemon bundle over `client` and stores it under
/// `providers/<provider>/guest/`. On failure writes `error.txt` there,
/// records a collector error, and falls back to reading the data volume image
/// from the host ([`volume_fallback`]) — `min bug` always produces a bundle,
/// and a dead transport is exactly when the guest's logs matter.
pub async fn collect(
    w: &mut BundleWriter,
    provider: &str,
    provider_dir: &Path,
    client: &mut Client,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let started = Instant::now();
    let req = minimald_rpc::DiagBundleRequest::default();

    let result = tokio::time::timeout(
        timeout,
        client.download_diag_bundle(&req, GUEST_BUNDLE_MAX_BYTES),
    )
    .await;

    let dest = format!("providers/{provider}/guest/daemon-diag.tar.zst");
    let failure = match result {
        Ok(Ok((bytes, truncated))) => {
            // Verify before recording, but record either way (R7.3): a bundle
            // that fails its checks is still the only word from the daemon.
            let verdict = verify_nested_bundle(&bytes).await;
            // A truncated stream is still collected — the manifest entry's
            // redaction records that only the leading bytes survived.
            let redaction = if truncated {
                Redaction::Truncated
            } else {
                Redaction::None
            };
            w.add_bytes(&dest, &bytes, redaction).await?;
            if let Err(failed) = verdict {
                w.error(
                    format!("guest.{provider}.verify"),
                    format!("nested bundle stored unverified — {failed}"),
                    started.elapsed(),
                );
            }
            return Ok(());
        }
        Ok(Err(e)) => format!("guest bundle download failed: {e:#}"),
        Err(_) => format!("guest bundle download timed out after {timeout:?}"),
    };

    w.error(format!("guest.{provider}"), &failure, started.elapsed());
    w.add_bytes(
        &format!("providers/{provider}/guest/error.txt"),
        failure.as_bytes(),
        Redaction::None,
    )
    .await?;
    volume_fallback(w, provider, provider_dir).await
}

/// Verifies a nested guest bundle by **bounded streaming decode**: the
/// decompressed stream is drained into a sink, never materialized, and the
/// decode stops the moment a cap is breached (R7.3).
///
/// The `Err` names the check that failed, so the manifest says *why* the
/// nested bundle is untrusted rather than only that it is.
///
/// Byte accounting covers entry *content* only; tar headers and padding are
/// bounded by [`NESTED_MAX_ENTRIES`] instead (10k × 512 B), which keeps a
/// header-only bomb bounded without letting incompressible padding distort the
/// content ratio.
async fn verify_nested_bundle(bytes: &[u8]) -> Result<(), String> {
    let budget = (bytes.len() as u64)
        .saturating_mul(NESTED_EXPANSION_RATIO)
        .max(NESTED_MIN_BUDGET)
        .min(NESTED_MAX_DECOMPRESSED);

    let decoder = async_compression::tokio::bufread::ZstdDecoder::new(bytes);
    let mut entries = async_tar::Archive::new(decoder)
        .entries()
        .map_err(|e| format!("decode check: not a readable tar stream: {e}"))?;

    let mut decompressed: u64 = 0;
    let mut count: usize = 0;
    let mut has_manifest = false;
    while let Some(entry) = entries.next().await {
        let entry =
            entry.map_err(|e| format!("decode check: entry {} unreadable: {e}", count + 1))?;
        count += 1;
        if count > NESTED_MAX_ENTRIES {
            return Err(format!(
                "entry-count check: more than {NESTED_MAX_ENTRIES} entries"
            ));
        }
        if entry
            .path()
            .is_ok_and(|p| p.as_os_str() == std::ffi::OsStr::new("manifest.json"))
        {
            has_manifest = true;
        }
        // One byte past what is left of the budget: enough to observe the
        // breach, never enough to be one.
        let room = budget - decompressed;
        decompressed += tokio::io::copy(&mut entry.take(room + 1), &mut tokio::io::sink())
            .await
            .map_err(|e| format!("decode check: entry {count} body unreadable: {e}"))?;
        if decompressed > budget {
            return Err(format!(
                "size check: decompressed past the {budget}-byte budget \
                 ({NESTED_EXPANSION_RATIO}x of {} compressed, clamped to \
                 [{NESTED_MIN_BUDGET}, {NESTED_MAX_DECOMPRESSED}])",
                bytes.len()
            ));
        }
    }
    if !has_manifest {
        return Err("manifest check: no manifest.json in the nested bundle".to_string());
    }
    Ok(())
}

// ── R7.5: volume fallback ────────────────────────────────────────────────────

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
/// installed; otherwise leaves the exact offline command in the manifest.
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
        bytes: meta.as_ref().map(std::fs::Metadata::len),
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
        DEBUGFS_TIMEOUT,
        tokio::process::Command::new("debugfs")
            .args(["-c", "-R", &rdump])
            .arg(&image)
            // On timeout the dropped future must not leave debugfs scanning a
            // large image after its target TempDir is gone.
            .kill_on_drop(true)
            .output(),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            let harvested = harvest_dir(w, &dest_dir, &tmp.path().join("logs")).await;
            if harvested == 0 {
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
        Err(_) => w.skip(
            &dest_dir,
            format!("debugfs timed out after {DEBUGFS_TIMEOUT:?}; {hint}"),
        ),
    }
    Ok(())
}

/// Adds every regular file directly under `src` to the bundle under
/// `dest_dir`, tail-capped. Returns how many made it.
async fn harvest_dir(w: &mut BundleWriter, dest_dir: &str, src: &Path) -> usize {
    let Ok(mut entries) = tokio::fs::read_dir(src).await else {
        return 0;
    };
    let mut added = 0usize;
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry.file_type().await.is_ok_and(|t| t.is_file()) {
            continue;
        }
        let dest = format!("{dest_dir}/{}", entry.file_name().to_string_lossy());
        match w.add_file_tail(&dest, &entry.path(), LOG_TAIL_CAP).await {
            Ok(()) => added += 1,
            Err(e) => w.skip(&dest, format!("unreadable: {e}")),
        }
    }
    added
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    /// Packs `entries` into a tar+zstd blob the way a daemon would stream it.
    async fn pack(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        let mut builder = async_tar::Builder::new(encoder);
        for (path, contents) in entries {
            let mut header = async_tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(async_tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, path, *contents)
                .await
                .unwrap();
        }
        let mut encoder = builder.into_inner().await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    #[tokio::test]
    async fn a_well_formed_bundle_verifies() {
        let bytes = pack(&[("meta.json", b"{}"), ("manifest.json", b"{}")]).await;
        verify_nested_bundle(&bytes).await.unwrap();
    }

    #[tokio::test]
    async fn a_bundle_without_a_manifest_fails_the_manifest_check() {
        let bytes = pack(&[("meta.json", b"{}"), ("logs/minimald.log", b"hi")]).await;
        let err = verify_nested_bundle(&bytes).await.unwrap_err();
        assert!(err.starts_with("manifest check:"), "got: {err}");
    }

    /// A classic decompression bomb: an enormous run of zeros that zstd
    /// squeezes to a few hundred bytes. The decode must stop at the budget
    /// (the [`NESTED_MIN_BUDGET`] floor here, since 4× the tiny compressed
    /// size is far below it), orders of magnitude short of the real size.
    #[tokio::test]
    async fn a_decompression_bomb_fails_the_size_check() {
        // Comfortably past the floor so the size cap — not the entry cap —
        // is what trips; zeros decode fast enough that draining to the floor
        // costs the test nothing meaningful.
        let bomb = vec![0u8; (NESTED_MIN_BUDGET + 8 * 1024 * 1024) as usize];
        let bytes = pack(&[("manifest.json", b"{}"), ("bomb.bin", &bomb)]).await;
        assert!(
            (bytes.len() as u64).saturating_mul(NESTED_EXPANSION_RATIO) < NESTED_MIN_BUDGET,
            "test bomb must compress below the budget floor, got {} bytes",
            bytes.len()
        );
        let err = verify_nested_bundle(&bytes).await.unwrap_err();
        assert!(err.starts_with("size check:"), "got: {err}");
    }

    /// The other bomb shape: no content at all, just more members than any
    /// real bundle has. Header bytes are not charged against the byte budget,
    /// so only the entry cap can stop this one.
    #[tokio::test]
    async fn too_many_entries_fails_the_entry_check() {
        let names: Vec<String> = (0..=NESTED_MAX_ENTRIES).map(|i| format!("f{i}")).collect();
        let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b""[..])).collect();
        let bytes = pack(&entries).await;
        let err = verify_nested_bundle(&bytes).await.unwrap_err();
        assert!(err.starts_with("entry-count check:"), "got: {err}");
    }

    #[tokio::test]
    async fn a_truncated_stream_fails_the_decode_check() {
        let bytes = pack(&[("manifest.json", b"{}"), ("logs/a.log", &[b'x'; 4096])]).await;
        let err = verify_nested_bundle(&bytes[..bytes.len() / 2])
            .await
            .unwrap_err();
        assert!(err.starts_with("decode check:"), "got: {err}");
    }

    /// The volume fallback must always leave the stall-dating signal, even
    /// when there is no image at all to read.
    #[tokio::test]
    async fn volume_fallback_records_meta_for_a_missing_image() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("b.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        volume_fallback(&mut w, "local-0", tmp.path())
            .await
            .unwrap();
        w.finish(chrono::Utc::now(), Duration::ZERO).await.unwrap();

        let bytes = tokio::fs::read(&out).await.unwrap();
        let mut entries = async_tar::Archive::new(
            async_compression::tokio::bufread::ZstdDecoder::new(&bytes[..]),
        )
        .entries()
        .unwrap();
        let mut meta = None;
        while let Some(entry) = entries.next().await {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().ends_with("volume-meta.json") {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).await.unwrap();
                meta = Some(serde_json::from_slice::<serde_json::Value>(&buf).unwrap());
            }
        }
        assert_eq!(meta.expect("volume-meta.json")["exists"], false);
    }
}
