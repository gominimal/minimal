//! On-disk loadout discovery.
//!
//! A user's loadouts live at `<config>/minimal/loadouts/<name>.toml`
//! (where `<config>` is the platform-standard user config dir; the
//! caller resolves that path and hands it in here). The filename
//! stem *is* the loadout's identifier — the single place a loadout is
//! named, so a file and the loadout it defines can never disagree
//! about which one gets picked up.
//!
//! A file may still carry the vestigial `name` field. It no longer
//! names anything: [`read_loadout_file`] warns that the field isn't
//! required and drops it, taking the name from the filename either
//! way. That is a warning rather than an error so an older loadout
//! keeps working untouched.

use std::path::{Path, PathBuf};

use crate::core::loadout::{Loadout, LoadoutFile, LoadoutName};

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
    /// The filename stem itself isn't a valid loadout name (e.g.
    /// contains a path separator or NUL). Caught before parsing the
    /// TOML so the operator gets the concrete "your filename is bad"
    /// message instead of a downstream one about the contents.
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
    /// interacts with as the loadout identifier, and what
    /// [`read_loadout_file`] names the parsed loadout after.
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

/// Parse a single loadout file and name it after its filename stem,
/// which must be a valid [`LoadoutName`] (rejects path separators,
/// NUL, empty).
///
/// A `name` field inside the file is vestigial: it is warned about
/// and discarded, whether or not it agrees with the filename. Loading
/// continues either way — a stale `name` costs the user a warning,
/// not a broken session.
///
/// # Errors
///
/// See [`LoadError`].
pub fn read_loadout_file(path: &Path) -> Result<Loadout, LoadError> {
    // Validate the stem *before* reading the file so an operator
    // renaming to `~/foo/bar.toml` gets the specific "your filename
    // is bad" message instead of a downstream one about the contents.
    let file_stem_str = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let file_stem =
        LoadoutName::try_new(file_stem_str).map_err(|source| LoadError::InvalidStem {
            path: path.to_path_buf(),
            source,
        })?;

    let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file: LoadoutFile = toml::from_str(&contents).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    match DeclaredName::classify(file.declared_name(), &file_stem) {
        DeclaredName::Absent => {}
        DeclaredName::Redundant => tracing::warn!(
            path = %path.display(),
            loadout = %file_stem,
            "loadout `{file_stem}` declares a `name` field; a loadout is now named \
             after its file, so the field is no longer required and can be deleted",
        ),
        DeclaredName::Mismatched(declared) => tracing::warn!(
            path = %path.display(),
            loadout = %file_stem,
            declared_name = %declared,
            "loadout `{file_stem}` declares the name `{declared}`, which does not match \
             its filename; a loadout is now named after its file, so the field is no \
             longer required — using `{file_stem}` and ignoring the declared name",
        ),
    }

    Ok(file.into_loadout(file_stem))
}

/// How a loadout file's declared `name` field stands relative to the
/// filename it was read from — the classification behind
/// [`read_loadout_file`]'s warnings. The field carries no authority in
/// any of these cases; only what to tell the user differs.
#[derive(Debug, PartialEq, Eq)]
enum DeclaredName<'a> {
    /// No `name` field: the current, expected shape of a loadout file.
    Absent,
    /// A `name` field agreeing with the filename — harmless, but no
    /// longer required.
    Redundant,
    /// A `name` field disagreeing with the filename. The filename
    /// wins; the declared name it carries is discarded.
    Mismatched(&'a LoadoutName),
}

impl<'a> DeclaredName<'a> {
    /// Classify `declared` (a file's `name` field, if any) against the
    /// `file_stem` the loadout is actually named after.
    fn classify(declared: Option<&'a LoadoutName>, file_stem: &LoadoutName) -> Self {
        match declared {
            None => Self::Absent,
            Some(name) if name == file_stem => Self::Redundant,
            Some(name) => Self::Mismatched(name),
        }
    }
}

/// Enumerate every `*.toml` file in `dir` and try to parse each as a
/// [`Loadout`], named after its file. Returns one [`LoadoutEntry`]
/// per file, sorted by stem; parse failures are folded into the
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

    /// A loadout file with no `name` field — the current shape —
    /// takes its name from the filename.
    #[test]
    fn read_loadout_file_names_from_file_stem() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "dev.toml", r#"packages = ["helix"]"#);
        let loadout = read_loadout_file(&path).expect("valid loadout should load");
        assert_eq!(loadout.name().as_ref(), "dev");
    }

    /// A file still declaring the `name` it is filed under loads
    /// unchanged: the field is redundant, not wrong, so it costs a
    /// warning and nothing else.
    #[test]
    fn read_loadout_file_redundant_name_still_loads() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "dev.toml",
            "name = \"dev\"\npackages = [\"helix\"]\n",
        );
        let loadout = read_loadout_file(&path).expect("a redundant name is not an error");
        assert_eq!(loadout.name().as_ref(), "dev");
        assert_eq!(loadout.packages(), &["helix"]);
    }

    /// A loadout whose declared `name` disagrees with its filename
    /// still loads — under the filename. The declared name is
    /// discarded (the user is warned), so the loadout is reachable by
    /// exactly the name it is filed under.
    #[test]
    fn read_loadout_file_mismatched_name_is_discarded() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "dev.toml",
            "name = \"other\"\npackages = [\"helix\"]\n",
        );
        let loadout = read_loadout_file(&path).expect("a mismatched name is not an error");
        assert_eq!(loadout.name().as_ref(), "dev");
        assert_eq!(loadout.packages(), &["helix"]);
    }

    /// The warning classification behind those two paths, exercised
    /// directly: absent, agreeing, and disagreeing `name` fields.
    #[test]
    fn declared_name_classification() {
        let stem = LoadoutName::try_new("dev").unwrap();
        let same = LoadoutName::try_new("dev").unwrap();
        let other = LoadoutName::try_new("other").unwrap();
        assert_eq!(DeclaredName::classify(None, &stem), DeclaredName::Absent);
        assert_eq!(
            DeclaredName::classify(Some(&same), &stem),
            DeclaredName::Redundant
        );
        assert_eq!(
            DeclaredName::classify(Some(&other), &stem),
            DeclaredName::Mismatched(&other)
        );
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
        write_file(dir.path(), "beta.toml", r#"packages = ["zellij"]"#);
        write_file(dir.path(), "alpha.toml", r#"packages = ["helix"]"#);
        write_file(dir.path(), "readme.txt", "not a loadout");
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        // Malformed but present — should show up as an entry with
        // a `Parse` error, not skip the file entirely.
        write_file(dir.path(), "broken.toml", "= bad =");
        // A stale `name` field is no longer a failure: the entry
        // parses and is listed under its filename.
        write_file(dir.path(), "renamed.toml", r#"name = "different""#);

        let entries = list_loadouts(dir.path()).expect("should list");
        let stems: Vec<&str> = entries.iter().map(|e| e.file_stem.as_str()).collect();
        assert_eq!(stems, vec!["alpha", "beta", "broken", "renamed"]);

        assert!(entries[0].loadout.is_ok());
        assert!(entries[1].loadout.is_ok());
        assert!(matches!(entries[2].loadout, Err(LoadError::Parse { .. })));
        assert_eq!(
            entries[3]
                .loadout
                .as_ref()
                .expect("renamed")
                .name()
                .as_ref(),
            "renamed"
        );
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
