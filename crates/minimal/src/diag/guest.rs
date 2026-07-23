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

use std::path::{Path, PathBuf};
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
/// Host disk the volume harvest may spend staging `/logs` before the per-file
/// caps apply. `rdump` writes the whole tree out first, so without this the
/// only bound on a long-lived guest's logs is the host's free space.
const VOLUME_HARVEST_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Where e2fsprogs puts `debugfs` when a plain `PATH` lookup will not find it.
///
/// Resolving by bare name alone left R7.5 inert on the primary dev platform:
/// Homebrew keeps e2fsprogs keg-only, so `debugfs 1.47.4` sits installed and
/// unreachable while the manifest reports "debugfs unavailable (No such file
/// or directory)" — ENOENT on *exec*, not on the image, which reads as "the
/// tool is missing" when it is not. Linux has the same shape: `/sbin` is not
/// on a non-root user's `PATH`, and `min bug` is run by a user.
const DEBUGFS_FALLBACK_PATHS: [&str; 4] = [
    "/opt/homebrew/opt/e2fsprogs/sbin/debugfs",
    "/usr/local/opt/e2fsprogs/sbin/debugfs",
    "/usr/sbin/debugfs",
    "/sbin/debugfs",
];

/// Picks the `debugfs` to run: whatever `PATH` offers first — an operator who
/// put one there meant it — then the known install locations.
///
/// Falls back to the bare name when nothing is found, so an "unavailable"
/// diagnosis still comes from a real exec attempt rather than from this probe.
async fn debugfs_program() -> PathBuf {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let candidates = std::env::split_paths(&path_var)
        .map(|dir| dir.join("debugfs"))
        .chain(DEBUGFS_FALLBACK_PATHS.iter().map(PathBuf::from));
    for candidate in candidates {
        if tokio::fs::metadata(&candidate)
            .await
            .is_ok_and(|m| m.is_file())
        {
            return candidate;
        }
    }
    PathBuf::from("debugfs")
}

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
/// Headroom over the content budget for the stream-level cap, covering the tar
/// structure the content budget does not charge for: a 512-byte header plus up
/// to 512 bytes of padding per entry, bounded by [`NESTED_MAX_ENTRIES`].
///
/// Without it the stream cap bites *before* the per-entry accounting can, and a
/// genuine oversize bundle gets reported as an unreadable stream instead of by
/// the check that actually caught it — the caps still hold, but the manifest
/// stops naming the real cause.
const NESTED_STREAM_SLACK: u64 = (NESTED_MAX_ENTRIES as u64 + 1) * 1024;

/// What the guest step left in the bundle for one provider.
///
/// Read by [`crate::diag::collect::explain_absent_log_prefixes`], which uses
/// it to decide what may be said about `logs/minimald.log*` missing from the
/// host state dir. The distinction between the two nested variants is the
/// whole point: pointing a reader at a carrier that turns out not to hold the
/// logs is the same failure mode — a manifest claim the archive does not
/// back — as claiming plain absence over a bundle that does hold them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOutcome {
    /// A nested bundle that verified *and* was observed to carry
    /// `logs/minimald.log*`. Only this warrants naming it as the carrier.
    BundleWithDaemonLogs,
    /// A nested bundle whose daemon logs this run could not confirm: the
    /// download was truncated, verification failed, or the stream verified
    /// with no `logs/minimald.log*` entry in it.
    BundleUnconfirmed,
    /// Nothing from the daemon: skipped, unreachable, or the fetch failed.
    NoBundle,
}

/// Whether a verified nested bundle was seen to carry the daemon's own logs.
///
/// Only meaningful for a verification that ran to completion: the checks
/// return the instant a cap trips, so a failed verdict has seen only a prefix
/// of the stream and knows nothing about what the rest holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonLogs {
    Present,
    Absent,
}

/// The prefix a daemon bundle's own log entries carry, mirroring the
/// `logs/<file>` layout `minimald::diag` writes. The daemon streams rootless,
/// so nested entries are bare paths with no bundle-name directory above them.
const NESTED_DAEMON_LOG_PREFIX: &str = "logs/minimald.log";

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
) -> Result<GuestOutcome, anyhow::Error> {
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
            return Ok(match verdict {
                // A truncated download is never a confirmed carrier even if
                // the prefix that arrived happened to verify: what the tail
                // held is exactly what was lost.
                Ok(DaemonLogs::Present) if !truncated => GuestOutcome::BundleWithDaemonLogs,
                Ok(_) => GuestOutcome::BundleUnconfirmed,
                Err(failed) => {
                    w.error(
                        format!("guest.{provider}.verify"),
                        format!("nested bundle stored unverified — {failed}"),
                        started.elapsed(),
                    );
                    GuestOutcome::BundleUnconfirmed
                }
            });
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
    volume_fallback(w, provider, provider_dir)
        .await
        .map(|()| GuestOutcome::NoBundle)
}

/// Verifies a nested guest bundle by **bounded streaming decode**: the
/// decompressed stream is drained into a sink, never materialized, and the
/// decode stops the moment a cap is breached (R7.3).
///
/// The `Err` names the check that failed, so the manifest says *why* the
/// nested bundle is untrusted rather than only that it is. The `Ok` reports
/// whether the walk saw the daemon's own logs, which is what lets the log
/// collector name this bundle as their carrier without guessing.
///
/// Byte accounting covers entry *content* only; tar headers and padding are
/// bounded by [`NESTED_MAX_ENTRIES`] instead (10k × 512 B), which keeps a
/// header-only bomb bounded without letting incompressible padding distort the
/// content ratio.
async fn verify_nested_bundle(bytes: &[u8]) -> Result<DaemonLogs, String> {
    // `clamp` cannot panic here: the floor is a compile-time constant below the
    // ceiling (64 MiB < 1 GiB).
    let budget = (bytes.len() as u64)
        .saturating_mul(NESTED_EXPANSION_RATIO)
        .clamp(NESTED_MIN_BUDGET, NESTED_MAX_DECOMPRESSED);

    let decoder = async_compression::tokio::bufread::ZstdDecoder::new(bytes);
    // The per-entry accounting below cannot see everything. `async_tar` reads
    // GNU longname/longlink and PAX extension bodies to completion inside
    // `entries()` (`poll_read_all`, archive.rs) before yielding the entry they
    // belong to, so those bytes bypass both the byte budget and the entry
    // count — a tiny archive declaring one enormous, highly compressible
    // extension member would be decoded straight into memory. Capping the
    // decompressed stream at its source is the only bound that covers reads
    // this loop never performs.
    //
    // Set above the content budget by the tar structure's worth of headroom:
    // headers come out of this same allowance, so a cap of exactly the budget
    // would starve the last legitimate body read and report an oversize bundle
    // as a corrupt one.
    let limited =
        tokio::io::AsyncReadExt::take(decoder, budget.saturating_add(NESTED_STREAM_SLACK));
    let mut entries = async_tar::Archive::new(limited)
        .entries()
        .map_err(|e| format!("decode check: not a readable tar stream: {e}"))?;

    let mut decompressed: u64 = 0;
    let mut count: usize = 0;
    let mut has_manifest = false;
    let mut has_daemon_logs = false;
    while let Some(entry) = entries.next().await {
        let entry =
            entry.map_err(|e| format!("decode check: entry {} unreadable: {e}", count + 1))?;
        count += 1;
        if count > NESTED_MAX_ENTRIES {
            return Err(format!(
                "entry-count check: more than {NESTED_MAX_ENTRIES} entries"
            ));
        }
        // Both observations require a *regular file*: a directory or symlink
        // wearing the name is not the thing a reader would be sent to find.
        if entry.header().entry_type().is_file()
            && let Ok(path) = entry.path()
        {
            has_manifest |= path.as_os_str() == std::ffi::OsStr::new("manifest.json");
            has_daemon_logs |= path.to_string_lossy().starts_with(NESTED_DAEMON_LOG_PREFIX);
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
    Ok(if has_daemon_logs {
        DaemonLogs::Present
    } else {
        DaemonLogs::Absent
    })
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
    // "Absent" and "unreadable" are different diagnoses and must not collapse
    // into the same `exists: false`. This runs when the daemon is already
    // suspect, so "the image is not there" versus "the image is there and I
    // could not read it" is often the answer itself.
    let meta = match tokio::fs::metadata(&image).await {
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            w.error(
                format!("guest.{provider}.volume_fallback"),
                format!("stat {}: {e}", image.display()),
                std::time::Duration::ZERO,
            );
            None
        }
    };
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
    // Resolved once and quoted into the hint: when the harvest is declined or
    // fails, the reader gets the command that will actually run on this host,
    // not one that depends on their `PATH` looking like ours.
    let debugfs = debugfs_program().await;
    let hint = format!(
        "harvest offline with: {} -c -R 'rdump /logs .' {}",
        debugfs.display(),
        image.display()
    );
    // `rdump` writes the whole tree to disk before anything caps it, and the
    // deadline below bounds only how long that runs — not how much it writes.
    // A guest that has been logging for weeks would spend the host's free
    // space during `min bug`, which is a poor trade for a best-effort
    // fallback. Size the harvest first and decline one that does not fit.
    match logs_tree_bytes(&debugfs, &image).await {
        Ok(total) if total > VOLUME_HARVEST_MAX_BYTES => {
            w.skip(
                &dest_dir,
                format!(
                    "/logs is {total} bytes, over the {VOLUME_HARVEST_MAX_BYTES}-byte \
                     harvest budget — not spending that much host disk here; {hint}"
                ),
            );
            return Ok(());
        }
        Ok(_) => {}
        // Unsized is not a reason to refuse: `ls -l` may fail on a corrupt
        // image that `rdump` can still salvage something from, and that is
        // exactly the case this fallback exists for. The deadline still caps it.
        Err(e) => w.skip(
            format!("{dest_dir}/.size-check"),
            format!("could not size /logs before harvesting ({e}); proceeding"),
        ),
    }

    let tmp = tempfile::TempDir::new().context("tempdir for volume harvest")?;
    let rdump = format!("rdump /logs {}", tmp.path().display());
    let result = tokio::time::timeout(
        DEBUGFS_TIMEOUT,
        tokio::process::Command::new(&debugfs)
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
            // Only treat as successful if debugfs succeeded (zero exit) AND files
            // were harvested; a nonzero exit means the dump may be partial/corrupt.
            if !out.status.success() {
                let code = out.status.code().unwrap_or(-1);
                let first_err = String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("no stderr")
                    .to_string();
                w.skip(
                    &dest_dir,
                    format!("debugfs exited with code {code} ({first_err}); {hint}"),
                );
            } else if harvested == 0 {
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

/// Total size of the regular files `debugfs` reports directly under `/logs`.
///
/// `ls -l` prints one row per entry; the mode is column 2 and the size is
/// column 6. Only `100***` (regular file) rows count — directories and the
/// `.`/`..` entries carry sizes that are not payload. Rows that do not parse
/// are ignored rather than failing the check: this is a pre-flight estimate,
/// and the deadline remains the backstop.
async fn logs_tree_bytes(debugfs: &Path, image: &Path) -> Result<u64, String> {
    let out = tokio::time::timeout(
        DEBUGFS_TIMEOUT,
        tokio::process::Command::new(debugfs)
            .args(["-c", "-R", "ls -l /logs"])
            .arg(image)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("timed out after {DEBUGFS_TIMEOUT:?}"))?
    .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            match cols.as_slice() {
                [_, mode, ..] if !mode.starts_with("100") => None,
                [_, _, _, _, _, size, ..] => size.parse::<u64>().ok(),
                _ => None,
            }
        })
        .sum())
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
pub(crate) mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    /// Packs `entries` into a tar+zstd blob the way a daemon would stream it.
    pub(crate) async fn pack(entries: &[(&str, &[u8])]) -> Vec<u8> {
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

    /// The bypass that made the caps ornamental, and the one hole in R7.3's
    /// coverage. `async_tar` reads a PAX extension body to completion *inside*
    /// `entries()` (`poll_read_all`, archive.rs:386) before yielding the entry
    /// it describes, so those bytes reach neither the byte budget nor the
    /// entry counter in the verify loop: a tiny zstd blob declaring one
    /// enormous, highly compressible extension member could be decoded
    /// straight into the CLI's memory. The bound now sits *under* the parser —
    /// the decompressed stream is capped before `Archive::new` — so the read
    /// this loop cannot see is capped anyway and the parser hits EOF instead
    /// of a body.
    ///
    /// What this proves: the extension path is rejected, and by the stream cap
    /// rather than by anything in the loop. What it does not prove: peak
    /// allocation, which stays a structural argument.
    #[tokio::test]
    async fn a_pax_extension_bomb_is_stopped_by_the_stream_cap() {
        // Past the stream cap (budget + slack), not merely past the content
        // budget — the content budget is exactly what this entry shape evades.
        let body = vec![0u8; (NESTED_MIN_BUDGET + NESTED_STREAM_SLACK + 8 * 1024 * 1024) as usize];
        let encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        let mut builder = async_tar::Builder::new(encoder);
        let mut header = async_tar::Header::new_ustar();
        header.set_path("PaxHeaders/bomb").unwrap();
        header.set_entry_type(async_tar::EntryType::XHeader);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &body[..]).await.unwrap();
        let mut encoder = builder.into_inner().await.unwrap();
        encoder.shutdown().await.unwrap();
        let bytes = encoder.into_inner();

        assert!(
            (bytes.len() as u64).saturating_mul(NESTED_EXPANSION_RATIO) < NESTED_MIN_BUDGET,
            "the bomb must compress below the budget floor, got {} bytes",
            bytes.len()
        );
        let err = verify_nested_bundle(&bytes).await.unwrap_err();
        assert!(err.starts_with("decode check:"), "got: {err}");
    }

    /// The manifest may name a nested bundle as the daemon logs' carrier only
    /// when the verify walk actually saw them go past.
    #[tokio::test]
    async fn verification_reports_whether_the_daemon_logs_are_present() {
        let with = pack(&[
            ("manifest.json", b"{}"),
            ("logs/minimald.log.2026-07-16", b"guest daemon log\n"),
        ])
        .await;
        assert_eq!(
            verify_nested_bundle(&with).await.unwrap(),
            DaemonLogs::Present
        );

        // A bundle that verifies but carries only the *other* daemon's logs
        // is not a carrier for this prefix.
        let without = pack(&[
            ("manifest.json", b"{}"),
            ("logs/minvmd.log.2026-07-16", b"host daemon log\n"),
        ])
        .await;
        assert_eq!(
            verify_nested_bundle(&without).await.unwrap(),
            DaemonLogs::Absent
        );
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
