//! Selection of rotated log files for diagnostic bundles.

use std::path::{Path, PathBuf};

/// The newest `limit` files in `dir` whose names start with `prefix`,
/// newest first.
///
/// "Newest" is reverse-lexicographic filename order: rolling filenames embed
/// their rotation point after the prefix (`minimald.log.2026-07-15`), so the
/// lexicographically greatest name is the most recent. A missing or
/// unreadable `dir` yields an empty list — callers that need to distinguish
/// "no log dir" from "no matches" check the directory first.
pub async fn newest_rotated(dir: &Path, prefix: &str, limit: usize) -> Vec<PathBuf> {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return Vec::new();
    };
    let mut matches: Vec<PathBuf> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(prefix))
        {
            matches.push(path);
        }
    }
    matches.sort();
    matches.reverse();
    matches.truncate(limit);
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn newest_first_capped_and_prefix_filtered() {
        let tmp = tempfile::TempDir::new().unwrap();
        for day in 1..=7 {
            std::fs::write(tmp.path().join(format!("app.log.2026-07-{day:02}")), "").unwrap();
        }
        std::fs::write(tmp.path().join("other.log.2026-07-09"), "").unwrap();

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
    async fn missing_dir_is_empty() {
        assert!(
            newest_rotated(Path::new("/nonexistent/diag-log-dir"), "app.log", 5)
                .await
                .is_empty()
        );
    }
}
