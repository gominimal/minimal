//! The Minimal standard library (embedded)

use std::{
    fs::{self, File, OpenOptions},
    io::{Error, Write},
    path::{Path, PathBuf},
};

include!(concat!(env!("OUT_DIR"), "/stdlib_files.rs"));

pub const HASH: &str = env!("STDLIB_HASH");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Upserts the minimal standard library to files on disk within the given dir. The
/// exact subdir of the standard library (to use as an import path) is returned.
pub fn upsert_stdlib_to_disk<P: AsRef<Path>>(cache_dir: P) -> Result<PathBuf, Error> {
    let cache_dir = cache_dir.as_ref();
    let dir = cache_dir.join(format!("{}-{}", VERSION, HASH));

    fs::create_dir_all(cache_dir)?;
    let mut lock = fd_lock::RwLock::new(
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(cache_dir.join("stdlib.lock"))?,
    );
    let _guard = lock.write()?;

    if stdlib_is_complete(&dir)? {
        return Ok(dir);
    }

    remove_incomplete_entry(&dir)?;

    let staging = tempfile::Builder::new()
        .prefix(&format!(".{}-{}-", VERSION, HASH))
        .tempdir_in(cache_dir)?;

    for StdlibFile { path, contents } in STDLIB_FILES {
        let mut file = File::create(staging.path().join(path))?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    File::open(staging.path())?.sync_all()?;

    if let Err(rename_error) = fs::rename(staging.path(), &dir) {
        if !stdlib_is_complete(&dir)? {
            return Err(rename_error);
        }
    } else {
        File::open(cache_dir)?.sync_all()?;
    }

    Ok(dir)
}

fn stdlib_is_complete(dir: &Path) -> Result<bool, Error> {
    if !dir.is_dir() {
        return Ok(false);
    }

    STDLIB_FILES.iter().try_fold(true, |complete, file| {
        if !complete {
            return Ok(false);
        }

        match fs::read(dir.join(file.path)) {
            Ok(contents) => Ok(contents == file.contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    })
}

fn remove_incomplete_entry(path: &Path) -> Result<(), Error> {
    let result = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };

    match result {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
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
    use std::{fs, thread};

    use tempfile::tempdir;

    use super::{STDLIB_FILES, upsert_stdlib_to_disk};

    #[test]
    fn version_less_than() {
        assert!(!super::version_greater_than("0.0.8", "0.0.9"));
        assert!(!super::version_greater_than("0.0.9", "0.0.9"));
        assert!(super::version_greater_than("0.0.10", "0.0.9"));
    }

    #[test]
    fn repairs_incomplete_stdlib() {
        let cache = tempdir().unwrap();
        let stdlib_dir = upsert_stdlib_to_disk(cache.path()).unwrap();
        fs::write(
            stdlib_dir.join(STDLIB_FILES[0].path),
            &STDLIB_FILES[0].contents[..1],
        )
        .unwrap();

        let repaired = upsert_stdlib_to_disk(cache.path()).unwrap();

        assert_eq!(repaired, stdlib_dir);
        assert!(
            STDLIB_FILES
                .iter()
                .all(|file| { fs::read(repaired.join(file.path)).unwrap() == file.contents })
        );
    }

    #[test]
    fn repairs_corrupt_stdlib() {
        let cache = tempdir().unwrap();
        let stdlib_dir = upsert_stdlib_to_disk(cache.path()).unwrap();
        let corrupt = vec![0; STDLIB_FILES[0].contents.len()];
        fs::write(stdlib_dir.join(STDLIB_FILES[0].path), corrupt).unwrap();

        let repaired = upsert_stdlib_to_disk(cache.path()).unwrap();

        assert!(
            STDLIB_FILES
                .iter()
                .all(|file| { fs::read(repaired.join(file.path)).unwrap() == file.contents })
        );
    }

    #[test]
    fn concurrent_upserts_install_one_complete_stdlib() {
        let cache = tempdir().unwrap();

        thread::scope(|scope| {
            let handles = (0..8)
                .map(|_| scope.spawn(|| upsert_stdlib_to_disk(cache.path())))
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .for_each(|handle| assert!(handle.join().unwrap().is_ok()));
        });

        let stdlib_dir = upsert_stdlib_to_disk(cache.path()).unwrap();
        assert!(
            STDLIB_FILES
                .iter()
                .all(|file| { fs::read(stdlib_dir.join(file.path)).unwrap() == file.contents })
        );
    }

    #[test]
    fn concurrent_upserts_repair_incomplete_stdlib() {
        let cache = tempdir().unwrap();
        let stdlib_dir = upsert_stdlib_to_disk(cache.path()).unwrap();
        fs::write(stdlib_dir.join(STDLIB_FILES[0].path), []).unwrap();

        thread::scope(|scope| {
            let handles = (0..8)
                .map(|_| scope.spawn(|| upsert_stdlib_to_disk(cache.path())))
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .for_each(|handle| assert!(handle.join().unwrap().is_ok()));
        });

        assert!(
            STDLIB_FILES
                .iter()
                .all(|file| { fs::read(stdlib_dir.join(file.path)).unwrap() == file.contents })
        );
    }
}
