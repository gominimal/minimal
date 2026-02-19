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
