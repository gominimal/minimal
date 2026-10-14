//! The local telemetry spool in a bundle (spec 25 TEL-044).
//!
//! The CLI's host bundle and the daemon's own bundle both carry a spool
//! directory's `*.jsonl` files the same way; only how many files travel and
//! what an absent directory is called differ, so those are the caller's.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bundle::{BundleSink, BundleWriter};

/// Which of a spool directory's files travel, newest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolKeep {
    /// The newest `n` files in all.
    Newest(usize),
    /// The newest `n` files of each [`producer`], so a chatty producer
    /// cannot push another's only file out of the bundle.
    NewestPerProducer(usize),
}

/// The producer a spool file belongs to: its name up to the first
/// `-<digit>`, which for mlog's `<service>-<pid>-<start_ms>[-<n>].jsonl` is
/// the service (`minimal-cli`, `minvmd`, `minimald`).
pub fn producer(name: &str) -> &str {
    let stem = name.strip_suffix(".jsonl").unwrap_or(name);
    let bytes = stem.as_bytes();
    let end = bytes
        .windows(2)
        .position(|w| matches!(w, [b'-', d] if d.is_ascii_digit()))
        .unwrap_or(bytes.len());
    // `end` is the index of an ASCII `-` or the length: a char boundary.
    stem.get(..end).unwrap_or(stem)
}

/// The spool files in `dir` into `telemetry/spool/<name>`: the `*.jsonl`
/// regular files `keep` selects, each tail-capped at `cap` bytes through
/// [`BundleWriter::add_spool_tail`]. Neither one of `header_values` (the
/// collecting process's own), nor one of the header values of the process
/// that wrote the file when it still runs
/// ([`crate::redact::spool_file_header_values`]), nor a secret-shaped or
/// header-like attribute's value travels.
///
/// The symlink guards are the logs': the directory is refused when it is not
/// a directory (a symlink included), a file is listed only when it is a
/// regular file, and the read itself does not follow a link. A missing
/// directory is skipped with `absent` as the reason; a listing that stops
/// early keeps the files already listed and says so in the manifest.
pub async fn collect<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dir: &Path,
    cap: u64,
    keep: SpoolKeep,
    header_values: &[String],
    absent: &str,
) -> Result<(), anyhow::Error> {
    match tokio::fs::symlink_metadata(dir).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            w.skip("telemetry/spool/", absent);
            return Ok(());
        }
        Err(e) => {
            w.skip("telemetry/spool/", format!("unreadable: {e}"));
            return Ok(());
        }
        Ok(m) if !m.is_dir() => {
            w.skip(
                "telemetry/spool/",
                "not a directory — refusing to follow it out of the state dir",
            );
            return Ok(());
        }
        Ok(_) => {}
    }
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) => {
            w.skip("telemetry/spool/", format!("unreadable: {e}"));
            return Ok(());
        }
    };
    let mut files: Vec<(SystemTime, PathBuf)> = Vec::new();
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            // The files already listed travel, and the manifest says the
            // listing did not finish.
            Err(e) => {
                w.skip(
                    "telemetry/spool/ (remainder)",
                    format!("listing stopped early: {e}"),
                );
                break;
            }
        };
        let path = entry.path();
        if !path.extension().is_some_and(|x| x == "jsonl") {
            continue;
        }
        // Spool-named files only: a pinned directory may hold a stranger's
        // `.jsonl`, and the scrubs are written for OTLP lines, not for it.
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_spool_file)
        {
            continue;
        }
        if let Ok(m) = tokio::fs::symlink_metadata(&path).await
            && m.is_file()
        {
            files.push((m.modified().unwrap_or(UNIX_EPOCH), path));
        }
    }
    if files.is_empty() {
        w.skip("telemetry/spool/*.jsonl", "no spool files");
        return Ok(());
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.0));
    match keep {
        SpoolKeep::Newest(n) => files.truncate(n),
        SpoolKeep::NewestPerProducer(n) => {
            // Newest first, so the first `n` of each producer stay.
            let mut kept: HashMap<String, usize> = HashMap::new();
            files.retain(|(_, path)| {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let seen = kept.entry(producer(&name).to_owned()).or_insert(0);
                *seen += 1;
                *seen <= n
            });
        }
    }
    for (_, path) in files {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let dest = format!("telemetry/spool/{name}");
        // The producer's own header set where it is known: a minvmd or
        // daemon started with headers the collecting process lacks.
        let values = crate::redact::spool_file_header_values(&name, header_values);
        if let Err(e) = w.add_spool_tail(&dest, &path, cap, &values).await {
            w.skip(&dest, format!("unreadable: {e:#}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::producer;

    #[test]
    fn spool_producer_is_the_service() {
        assert_eq!(producer("minimal-cli-7-1700000000000.jsonl"), "minimal-cli");
        assert_eq!(producer("minvmd-42-1700000000000-3.jsonl"), "minvmd");
        assert_eq!(producer("a_b-1-9999999999999-12.jsonl"), "a_b");
        assert_eq!(producer("report.jsonl"), "report");
    }
}

/// Whether `name` is a spool writer's file name, `<service>-<pid>-<start_ms>[-<n>].jsonl`:
/// a verbatim port of `mlog::otel::spool::SpoolName::parse` (this crate does
/// not depend on `mlog`), so the bundle takes exactly the files the writer
/// names and the pruner bounds, and nothing else a pinned directory holds. A
/// number has no leading zero; the pid is a `u32`, the start exactly 13
/// digits, the rotation a `u64`; the service is `[A-Za-z0-9_-]+`.
pub(crate) fn is_spool_file(name: &str) -> bool {
    fn number<T: std::str::FromStr>(s: &str) -> Option<T> {
        (!s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    }
    fn stem(s: &str) -> bool {
        let mut parts = s.rsplitn(3, '-');
        let (Some(start), Some(pid), Some(service)) = (parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        start.len() == 13
            && number::<u64>(start).is_some()
            && number::<u32>(pid).is_some()
            && !service.is_empty()
            && service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }
    let Some(s) = name.strip_suffix(".jsonl") else {
        return false;
    };
    if stem(s) {
        return true;
    }
    s.rsplit_once('-')
        .is_some_and(|(rest, n)| number::<u64>(n).is_some() && stem(rest))
}

#[cfg(test)]
mod spool_name_tests {
    use super::is_spool_file;

    #[test]
    fn spool_names_are_taken_and_strangers_are_not() {
        for ok in [
            "minimald-1234-1700000000000.jsonl",
            "minimald-1234-1700000000000-7.jsonl",
            "guest-vm-a-1-1700000000000.jsonl",
            "min_cli-4294967295-9999999999999-12.jsonl",
        ] {
            assert!(is_spool_file(ok), "{ok}");
        }
        for no in [
            "events.jsonl",
            "api-keys.jsonl",
            "minimald-0-1700000000000.jsonl",
            "minimald-01234-1700000000000.jsonl",
            "minimald-4294967296-1700000000000.jsonl",
            "minimald-1234-170000000000.jsonl",
            "minimald-1234-0700000000000.jsonl",
            "minimald-1234-1700000000000-0.jsonl",
            "minimald-1234-1700000000000-07.jsonl",
            "minimald-1234-1700000000000.json",
            "minimald-abc-1700000000000.jsonl",
            "-1234-1700000000000.jsonl",
        ] {
            assert!(!is_spool_file(no), "{no}");
        }
    }
}
