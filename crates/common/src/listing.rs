//! Metadata-only directory listings for diagnostic bundles.
//!
//! Shared by the `min bug` host collectors and the minimald diagnostic RPC:
//! both need to show *what exists* (names, sizes, types, modes) without ever
//! copying file contents.

use std::path::Path;

/// One `type\tsize\tmtime\tmode\tpath` line per entry under `root`,
/// depth-first with sorted siblings (deterministic, diffable), capped at
/// `max_entries` with an explicit truncation marker.
pub fn listing_text(root: &Path, max_entries: usize) -> String {
    let mut out = String::from("type\tsize\tmtime\tmode\tpath\n");
    let mut count = 0usize;
    walk_listing(root, root, &mut out, &mut count, max_entries);
    if count >= max_entries {
        out.push_str("<truncated: listing cap reached>\n");
    }
    out
}

fn walk_listing(root: &Path, dir: &Path, out: &mut String, count: &mut usize, max: usize) {
    use std::fmt::Write as _;
    use std::os::unix::fs::MetadataExt as _;

    let Ok(entries) = std::fs::read_dir(dir) else {
        let rel = dir.strip_prefix(root).unwrap_or(dir).display();
        let _ = writeln!(out, "?\t-\t-\t-\t{rel}/ <unreadable>");
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        if *count >= max {
            return;
        }
        *count += 1;
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let (kind, size, mtime, mode) = match entry.metadata() {
            Ok(m) => (
                file_kind(&m),
                m.len().to_string(),
                m.mtime().to_string(),
                format!("{:o}", m.mode() & 0o7777),
            ),
            Err(_) => ('?', "-".into(), "-".into(), "-".into()),
        };
        let _ = writeln!(out, "{kind}\t{size}\t{mtime}\t{mode}\t{}", rel.display());
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            walk_listing(root, &path, out, count, max);
        }
    }
}

fn file_kind(meta: &std::fs::Metadata) -> char {
    let ft = meta.file_type();
    if ft.is_dir() {
        'd'
    } else if ft.is_symlink() {
        'l'
    } else if ft.is_file() {
        'f'
    } else {
        's' // socket/fifo/device — "special"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_is_metadata_only_and_sorted() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("b-dir")).unwrap();
        std::fs::write(tmp.path().join("b-dir/inner.txt"), "contents!").unwrap();
        std::fs::write(tmp.path().join("a.txt"), "secret-data").unwrap();

        let listing = listing_text(tmp.path(), 100_000);
        let lines: Vec<&str> = listing.lines().collect();
        assert!(lines[1].ends_with("\ta.txt"), "got: {}", lines[1]);
        assert!(lines[1].starts_with("f\t11\t"), "got: {}", lines[1]);
        assert!(lines[2].ends_with("\tb-dir"), "got: {}", lines[2]);
        assert!(lines[3].ends_with("b-dir/inner.txt"), "got: {}", lines[3]);
        assert!(
            !listing.contains("secret-data") && !listing.contains("contents!"),
            "listing must never include file contents"
        );
    }

    #[test]
    fn listing_truncates_at_the_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        for i in 0..10 {
            std::fs::write(tmp.path().join(format!("f{i}")), "").unwrap();
        }
        let listing = listing_text(tmp.path(), 3);
        assert_eq!(listing.lines().count(), 1 + 3 + 1, "header + 3 + marker");
        assert!(listing.ends_with("<truncated: listing cap reached>\n"));
    }
}
