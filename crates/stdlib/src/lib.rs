//! The Minimal standard library (embedded)

use std::{
    fs::{create_dir_all, exists, write},
    io::Error,
    path::{Path, PathBuf},
};

include!(concat!(env!("OUT_DIR"), "/stdlib_files.rs"));

pub const HASH: &str = env!("STDLIB_HASH");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Upserts the minimal standard library to files on disk within the given dir. The
/// exact subdir of the standard library (to use as an import path) is returned.
pub fn upsert_stdlib_to_disk<P: AsRef<Path>>(cache_dir: P) -> Result<PathBuf, Error> {
    let dir = cache_dir.as_ref().join(format!("{}-{}", VERSION, HASH));

    if !exists(&dir)? {
        create_dir_all(&dir)?;
        for StdlibFile { path, contents } in STDLIB_FILES {
            write(dir.join(path), contents)?;
        }
    }

    Ok(dir)
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.').map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

fn version_greater_than(lhs: &str, rhs: &str) -> bool {
    match (parse_version(lhs), parse_version(rhs)) {
        (Some(lhs), Some(rhs)) => lhs > rhs,
        _ => true,
    }
}

/// Returns true if the minimum version of the standard library cannot be supported.
pub fn outdated(min_version: &str) -> bool {
    version_greater_than(min_version, VERSION)
}

#[cfg(test)]
mod tests {

    #[test]
    fn version_less_than() {
        assert!(!super::version_greater_than("0.0.8", "0.0.9"));
        assert!(!super::version_greater_than("0.0.9", "0.0.9"));
        assert!(super::version_greater_than("0.0.10", "0.0.9"));
    }
}
