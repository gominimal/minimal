//! Selection of rotated log files for diagnostic bundles.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The newest `limit` files in `dir` whose names start with `prefix`,
/// newest first.
///
/// "Newest" is modified-time order, which is rotation-scheme agnostic: it is
/// correct for date-suffixed rolling names (`app.log.2026-07-15`) and for
/// logrotate-style numeric shifting (`app.log` live, `app.log.1` the most
/// recently rotated) alike — filename order is not, since the two schemes
/// sort in opposite directions. Name order (descending) breaks ties for
/// determinism. A missing or unreadable `dir` yields an empty list — callers
/// that need to distinguish "no log dir" from "no matches" check the
/// directory first.
pub async fn newest_rotated(dir: &Path, prefix: &str, limit: usize) -> Vec<PathBuf> {
    newest_matching(dir, limit, |name| name.starts_with(prefix)).await
}

/// The newest `limit` files in `dir` whose names satisfy `keep`, newest
/// first — the general form of [`newest_rotated`] for selections that are not
/// prefix-shaped (crash reports picked out by their `.panic` extension).
/// Same ordering and same missing-dir behavior.
pub async fn newest_matching(
    dir: &Path,
    limit: usize,
    keep: impl Fn(&str) -> bool,
) -> Vec<PathBuf> {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return Vec::new();
    };
    let mut matches: Vec<(SystemTime, PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()).is_some_and(&keep) {
            let mtime = entry
                .metadata()
                .await
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            matches.push((mtime, path));
        }
    }
    matches.sort_by(|(at, ap), (bt, bp)| bt.cmp(at).then_with(|| bp.cmp(ap)));
    matches.truncate(limit);
    matches.into_iter().map(|(_, path)| path).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn write_with_mtime(path: &Path, age_secs: u64) {
        let file = std::fs::File::create(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(age_secs))
            .unwrap();
    }

    #[tokio::test]
    async fn newest_first_capped_and_prefix_filtered() {
        let tmp = tempfile::TempDir::new().unwrap();
        for day in 1..=7 {
            // Older dates get older mtimes, as rotation produces them.
            write_with_mtime(
                &tmp.path().join(format!("app.log.2026-07-{day:02}")),
                (8 - day) * 100,
            );
        }
        write_with_mtime(&tmp.path().join("other.log.2026-07-09"), 1);

        let picked = newest_rotated(tmp.path(), "app.log", 5).await;
        let names: Vec<&str> = picked
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "app.log.2026-07-07",
                "app.log.2026-07-06",
                "app.log.2026-07-05",
                "app.log.2026-07-04",
                "app.log.2026-07-03",
            ],
            "newest five, other prefixes excluded"
        );
    }

    #[tokio::test]
    async fn logrotate_style_numeric_suffixes_order_by_recency() {
        let tmp = tempfile::TempDir::new().unwrap();
        // logrotate-style shift: the live file is newest, `.1` the most
        // recently rotated, higher suffixes older. Reverse filename order
        // would return exactly the wrong end of this list.
        write_with_mtime(&tmp.path().join("app.log"), 0);
        write_with_mtime(&tmp.path().join("app.log.1"), 100);
        write_with_mtime(&tmp.path().join("app.log.2"), 200);
        write_with_mtime(&tmp.path().join("app.log.10"), 1000);

        let picked = newest_rotated(tmp.path(), "app.log", 3).await;
        let names: Vec<&str> = picked
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["app.log", "app.log.1", "app.log.2"]);
    }

    #[tokio::test]
    async fn missing_dir_is_empty() {
        assert!(
            newest_rotated(Path::new("/nonexistent/diag-log-dir"), "app.log", 5)
                .await
                .is_empty()
        );
    }
}
