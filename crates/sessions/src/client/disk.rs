//! On-disk loadout discovery.
//!
//! A user's loadouts live at `<config>/minimal/loadouts/<name>.toml`
//! (where `<config>` is the platform-standard user config dir; the
//! caller resolves that path and hands it in here). The filename
//! stem is the loadout's identifier: it must match the loadout's
//! declared `name` field, otherwise loading errors out — divergent
//! references between the filename and the internal name would be a
//! confusing source of "which one gets picked up" bugs.

use std::path::{Path, PathBuf};

use crate::core::loadout::Loadout;

/// Failure loading a single loadout file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file couldn't be read.
    #[error("read `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file wasn't valid TOML or didn't match the [`Loadout`]
    /// schema.
    #[error("parse `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// The loadout's declared `name` field disagrees with the file
    /// stem it was loaded from.
    #[error(
        "loadout at `{path}` declares name `{declared_name}` but the filename \
         stem is `{file_stem}`; rename the file or fix the `name` field"
    )]
    NameMismatch {
        path: PathBuf,
        /// The filename stem the file was found under — the
        /// user-facing loadout identifier that must match `name`.
        file_stem: String,
        /// The value inside the file's `name = "..."` field, which
        /// disagreed with `file_stem`.
        declared_name: String,
    },
    /// The filename stem itself isn't a valid loadout name (e.g.
    /// contains a path separator or NUL). Caught before parsing the
    /// TOML so the operator gets the concrete "your filename is bad"
    /// message instead of a downstream "name mismatch" one.
    #[error("loadout file `{path}` has an invalid stem: {source}")]
    InvalidStem {
        path: PathBuf,
        #[source]
        source: crate::core::loadout::LoadoutNameError,
    },
}

/// A directory entry produced by [`list_loadouts`]: the filename
/// stem this entry was found under, and either the parsed
/// [`Loadout`] or the error that prevented parsing.
#[derive(Debug)]
#[non_exhaustive]
pub struct LoadoutEntry {
    /// The filename stem (without `.toml`). This is what the user
    /// interacts with as the loadout identifier — [`read_loadout_file`]
    /// enforces that it matches the loadout's internal `name` field.
    pub file_stem: String,
    /// Path to the loadout file. Absolute when `list_loadouts`
    /// canonicalized the input directory (its normal path); may be
    /// relative if the caller invoked `read_loadout_file` directly
    /// with a relative argument.
    pub path: PathBuf,
    /// The parsed loadout, or the error explaining why it couldn't
    /// be loaded. Listing surfaces malformed entries so an operator
    /// can fix them; consumers that need only usable loadouts should
    /// filter on `Ok`.
    pub loadout: Result<Loadout, LoadError>,
}

/// Failure enumerating the loadouts directory itself. Distinct from
/// per-entry [`LoadError`]s, which are folded into [`LoadoutEntry`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
    /// The directory doesn't exist.
    #[error("loadouts directory `{path}` does not exist")]
    NotFound { path: PathBuf },
    /// The path exists but isn't a directory.
    #[error("`{path}` is not a directory")]
    NotADirectory { path: PathBuf },
    /// Reading the directory failed for some other reason (permissions,
    /// I/O error, etc.).
    #[error("read directory `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Parse a single loadout file. The file stem must be a valid
/// [`LoadoutName`] (rejects path separators, NUL, empty) and must
/// match the loadout's declared `name` field.
///
/// # Errors
///
/// See [`LoadError`].
pub fn read_loadout_file(path: &Path) -> Result<Loadout, LoadError> {
    // Validate the stem *before* reading the file so an operator
    // renaming to `~/foo/bar.toml` gets the specific "your filename
    // is bad" message instead of a confusing name-mismatch error
    // downstream.
    let file_stem_str = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let file_stem =
        crate::core::loadout::LoadoutName::try_new(file_stem_str).map_err(|source| {
            LoadError::InvalidStem {
                path: path.to_path_buf(),
                source,
            }
        })?;

    let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let loadout: Loadout = toml::from_str(&contents).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    if loadout.name() != &file_stem {
        return Err(LoadError::NameMismatch {
            path: path.to_path_buf(),
            file_stem: file_stem.into_inner(),
            declared_name: loadout.name().as_ref().to_string(),
        });
    }
    Ok(loadout)
}

/// Enumerate every `*.toml` file in `dir` and try to parse each as a
/// [`Loadout`]. Returns one [`LoadoutEntry`] per file, sorted by
/// stem; parse and name-mismatch failures are folded into the
/// entry's `loadout` field so the caller can surface them in the
/// listing rather than aborting the whole scan.
///
/// Non-`.toml` files and subdirectories are silently ignored.
///
/// # Errors
///
/// See [`ListError`].
pub fn list_loadouts(dir: &Path) -> Result<Vec<LoadoutEntry>, ListError> {
    // Canonicalize once up front so every `LoadoutEntry.path` is
    // absolute (matches the docstring on that field) and so any
    // downstream logging or error message names the real path
    // instead of a `-r ./foo`-shaped relative one. Absence is
    // reported below as `ListError::NotFound` uniformly.
    let dir = std::fs::canonicalize(dir).map_err(|source| match source.kind() {
        std::io::ErrorKind::NotFound => ListError::NotFound {
            path: dir.to_path_buf(),
        },
        _ => ListError::Io {
            path: dir.to_path_buf(),
            source,
        },
    })?;
    let read_dir = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(source) if source.kind() == std::io::ErrorKind::NotADirectory => {
            return Err(ListError::NotADirectory { path: dir });
        }
        Err(source) => {
            return Err(ListError::Io { path: dir, source });
        }
    };

    let mut entries: Vec<LoadoutEntry> = read_dir
        .filter_map(|res| match res {
            Ok(entry) => Some(entry),
            Err(e) => {
                // Per-dirent errors are typically transient
                // (permission-denied on a specific entry, a race
                // where the file vanished between opendir/readdir).
                // Surface via a warn instead of silently swallowing;
                // the module's convention is to make errors visible.
                tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "skipping loadouts directory entry: read failed",
                );
                None
            }
        })
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                return None;
            }
            let file_stem = path.file_stem().and_then(|s| s.to_str())?.to_string();
            let loadout = read_loadout_file(&path);
            Some(LoadoutEntry {
                file_stem,
                path,
                loadout,
            })
        })
        .collect();
    entries.sort_by(|a, b| a.file_stem.cmp(&b.file_stem));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    /// A well-formed loadout file loads and its name field matches
    /// the file stem.
    #[test]
    fn read_loadout_file_ok() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "dev.toml", r#"name = "dev""#);
        let loadout = read_loadout_file(&path).expect("valid loadout should load");
        assert_eq!(loadout.name().as_ref(), "dev");
    }

    /// A loadout whose declared `name` disagrees with its filename
    /// stem is rejected with a descriptive error.
    #[test]
    fn read_loadout_file_name_mismatch_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "dev.toml", r#"name = "other""#);
        let err = read_loadout_file(&path).expect_err("mismatched name should error");
        match err {
            LoadError::NameMismatch {
                file_stem,
                declared_name,
                ..
            } => {
                assert_eq!(file_stem, "dev");
                assert_eq!(declared_name, "other");
            }
            other => panic!("expected NameMismatch, got {other:?}"),
        }
    }

    /// Malformed TOML is reported as a `Parse` error, not swallowed.
    #[test]
    fn read_loadout_file_parse_error() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bad.toml", "= not = toml =");
        let err = read_loadout_file(&path).expect_err("malformed toml should error");
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    /// `list_loadouts` enumerates `.toml` files in stem order,
    /// ignores non-`.toml` entries and subdirectories, and folds
    /// per-entry errors into the returned list rather than aborting.
    #[test]
    fn list_loadouts_enumerates_and_sorts() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "beta.toml", r#"name = "beta""#);
        write_file(dir.path(), "alpha.toml", r#"name = "alpha""#);
        write_file(dir.path(), "readme.txt", "not a loadout");
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        // Malformed but present — should show up as an entry with
        // a `Parse` error, not skip the file entirely.
        write_file(dir.path(), "broken.toml", "= bad =");
        // Name-mismatch — also surfaces as an entry with an error.
        write_file(dir.path(), "renamed.toml", r#"name = "different""#);

        let entries = list_loadouts(dir.path()).expect("should list");
        let stems: Vec<&str> = entries.iter().map(|e| e.file_stem.as_str()).collect();
        assert_eq!(stems, vec!["alpha", "beta", "broken", "renamed"]);

        assert!(entries[0].loadout.is_ok());
        assert!(entries[1].loadout.is_ok());
        assert!(matches!(entries[2].loadout, Err(LoadError::Parse { .. })));
        assert!(matches!(
            entries[3].loadout,
            Err(LoadError::NameMismatch { .. })
        ));
    }

    /// A missing directory returns `NotFound`, not a generic I/O error.
    #[test]
    fn list_loadouts_missing_dir_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");
        let err = list_loadouts(&missing).expect_err("missing dir should error");
        assert!(matches!(err, ListError::NotFound { .. }));
    }
}
