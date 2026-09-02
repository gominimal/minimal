//! Upstream attribution files captured when a source is extracted.
//!
//! Some licenses require the upstream's *own* files to travel with a
//! distribution — Apache-2.0 §4(d) for `NOTICE`, verbatim copyright notices
//! for most permissive licenses. Only the builder ever holds the unpacked
//! source tree, so the capture happens here, once per source, and is stored
//! beside the cache as `<cache>/notices/<source-sha256>.json`. The
//! attribution manifest sealed downstream already names each package's
//! sources by sha256, which is the join key.

use std::io;
use std::path::{Path, PathBuf};

use lcache::{Cache, LocalDir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bump when the on-disk shape changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level files that count as attribution. Matched case-insensitively on
/// the stem, so `NOTICE`, `Notice.txt`, `COPYING.LIB`, and `COPYRIGHT.md` all
/// qualify while `LICENSE` (covered by the canonical SPDX text) does not.
const STEMS: &[&str] = &["NOTICE", "COPYRIGHT", "COPYING"];

/// Larger files are not attribution text; skipped rather than truncated.
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// Upstreams rarely ship more than a handful; a cap keeps a pathological tree
/// from turning into a large record.
const MAX_FILES: usize = 8;

/// One captured file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeFile {
    /// File name as it appears at the top of the source tree.
    pub name: String,
    /// Hex sha256 of the raw bytes.
    pub sha256: String,
    /// Contents, lossily decoded as UTF-8.
    pub text: String,
}

/// Everything captured from one source archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceNotices {
    pub schema_version: u32,
    /// Hex sha256 of the source archive, as declared in the build spec.
    pub source_sha256: String,
    /// Sorted by name. Empty when the tree ships nothing qualifying, which is
    /// recorded too so consumers can tell "scanned, none" from "never seen".
    pub files: Vec<NoticeFile>,
}

fn qualifies(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    STEMS.iter().any(|stem| {
        upper
            .strip_prefix(stem)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-', '_']))
    })
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Reads the qualifying regular files directly under `dir`. Symlinks and
/// directories are ignored — a symlink could point outside the tree.
fn scan_dir(dir: &Path) -> io::Result<Vec<NoticeFile>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !qualifies(&name) || !entry.file_type()?.is_file() {
            continue;
        }
        if entry.metadata()?.len() > MAX_FILE_BYTES {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        files.push(NoticeFile {
            name,
            sha256: hex::encode(Sha256::digest(&bytes)),
            text: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files.truncate(MAX_FILES);
    Ok(files)
}

/// Scans an extracted source tree rooted at `root`. When the archive kept its
/// single top-level directory (no `strip_prefix`), that directory is the tree.
pub fn scan(root: &Path) -> io::Result<Vec<NoticeFile>> {
    let files = scan_dir(root)?;
    if !files.is_empty() {
        return Ok(files);
    }
    let mut entries = std::fs::read_dir(root)?.collect::<io::Result<Vec<_>>>()?;
    match entries.pop() {
        Some(only) if entries.is_empty() && only.file_type()?.is_dir() => scan_dir(&only.path()),
        _ => Ok(files),
    }
}

fn record_path(cache: &Cache<LocalDir>, source_sha256: &str) -> PathBuf {
    cache.notices_dir().join(format!("{source_sha256}.json"))
}

/// Captures `root`'s attribution files under `source_sha256`. Idempotent:
/// an existing record is left alone, since the same archive always yields
/// the same tree. Returns the record's path.
pub fn record(cache: &Cache<LocalDir>, source_sha256: &str, root: &Path) -> io::Result<PathBuf> {
    if !is_sha256_hex(source_sha256) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a sha256 hex digest: {source_sha256:?}"),
        ));
    }
    let path = record_path(cache, source_sha256);
    if path.exists() {
        return Ok(path);
    }
    let notices = SourceNotices {
        schema_version: SCHEMA_VERSION,
        source_sha256: source_sha256.to_owned(),
        files: scan(root)?,
    };
    let json = serde_json_lenient::to_string_pretty(&notices).map_err(io::Error::other)?;
    // Write-then-rename so a reader never sees a partial record.
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Reads a record, `None` when the source has never been extracted here.
pub fn read(cache: &Cache<LocalDir>, source_sha256: &str) -> io::Result<Option<SourceNotices>> {
    if !is_sha256_hex(source_sha256) {
        return Ok(None);
    }
    match std::fs::read(record_path(cache, source_sha256)) {
        Ok(bytes) => serde_json_lenient::from_slice(&bytes)
            .map(Some)
            .map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SHA: &str = "4474de87e084953eefc1120cf905a79f72bbbf85091e30cf37c9214eafcaa9c9";

    fn tree(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        dir
    }

    #[test]
    fn stems_match_case_insensitively_with_suffixes() {
        for name in [
            "NOTICE",
            "notice",
            "Notice.txt",
            "NOTICE.md",
            "COPYING.LIB",
            "COPYRIGHT-2024",
            "copyright_notice",
        ] {
            assert!(qualifies(name), "{name}");
        }
        for name in [
            "LICENSE",
            "LICENSE-APACHE",
            "NOTICES",
            "NOTICEBOARD.txt",
            "README",
            "COPYINGX",
        ] {
            assert!(!qualifies(name), "{name}");
        }
    }

    #[test]
    fn scan_collects_only_qualifying_regular_files_sorted_by_name() {
        let dir = tree(&[
            ("NOTICE", "hello"),
            ("copying.txt", "c"),
            ("LICENSE", "l"),
            ("README", "r"),
        ]);
        std::fs::create_dir(dir.path().join("COPYRIGHT.d")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("NOTICE"), dir.path().join("NOTICE-link"))
            .unwrap();
        std::fs::write(
            dir.path().join("NOTICE.big"),
            vec![b'x'; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();

        let files = scan(dir.path()).unwrap();
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["NOTICE", "copying.txt"]);
        assert_eq!(
            files[0].sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(files[0].text, "hello");
    }

    #[test]
    fn scan_descends_into_a_lone_top_level_directory() {
        let dir = TempDir::new().unwrap();
        let top = dir.path().join("pkg-1.0");
        std::fs::create_dir(&top).unwrap();
        std::fs::write(top.join("NOTICE"), "n").unwrap();
        assert_eq!(scan(dir.path()).unwrap()[0].name, "NOTICE");

        // Two top-level entries: the tree is `root` itself, and it has nothing.
        std::fs::write(dir.path().join("README"), "r").unwrap();
        assert!(scan(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn record_writes_once_and_reads_back() {
        let cache_dir = TempDir::new().unwrap();
        let cache = Cache::at_dir(cache_dir.path()).unwrap();
        let src = tree(&[("NOTICE", "first")]);

        let path = record(&cache, SHA, src.path()).unwrap();
        assert_eq!(path, cache.notices_dir().join(format!("{SHA}.json")));
        let got = read(&cache, SHA).unwrap().unwrap();
        assert_eq!(got.schema_version, SCHEMA_VERSION);
        assert_eq!(got.source_sha256, SHA);
        assert_eq!(got.files.len(), 1);
        assert_eq!(got.files[0].text, "first");

        // A second extraction of the same archive does not rewrite the record.
        std::fs::write(src.path().join("NOTICE"), "changed").unwrap();
        record(&cache, SHA, src.path()).unwrap();
        assert_eq!(read(&cache, SHA).unwrap().unwrap().files[0].text, "first");

        // Nothing qualifying is still a record.
        let empty = tree(&[("LICENSE", "l")]);
        let other = "a".repeat(64);
        record(&cache, &other, empty.path()).unwrap();
        assert!(read(&cache, &other).unwrap().unwrap().files.is_empty());
        assert!(read(&cache, &"b".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn record_rejects_a_key_that_is_not_a_digest() {
        let cache_dir = TempDir::new().unwrap();
        let cache = Cache::at_dir(cache_dir.path()).unwrap();
        let src = tree(&[]);
        let err = record(&cache, "../escape", src.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(read(&cache, "../escape").unwrap().is_none());
    }
}
