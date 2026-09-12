//! On-disk loadout discovery.
//!
//! A user's loadouts live under `<config>/minimal/loadouts/` (where
//! `<config>` is the platform-standard user config dir; the caller
//! resolves that path and hands it in here), in either of two layouts:
//!
//! | [`Layout`] | Path | For |
//! |---|---|---|
//! | [`Flat`](Layout::Flat) | `<loadouts>/<name>.toml` | a loadout that is just a file |
//! | [`Directory`](Layout::Directory) | `<loadouts>/<name>/loadout.toml` | a loadout kept under version control |
//!
//! The two are equivalent in every way but where the bytes sit. A
//! loadout's own directory — the anchor for its `$LOADOUT_ROOT` patch
//! sources and its external hook scripts — is `<loadouts>/<name>/`
//! under both, because [`Source::loadout_dir`] derives it from the
//! *name* rather than from the file's path. So `mkdir dev && mv
//! dev.toml dev/loadout.toml` migrates a loadout with nothing else to
//! change, and the directory form simply puts the definition inside
//! the directory its files already lived in.
//!
//! Either way the **name comes from the filesystem**, never from
//! anything written inside the file: the filename stem under
//! [`Flat`](Layout::Flat), the directory name under
//! [`Directory`](Layout::Directory). That is the single place a
//! loadout is named, so a file and the loadout it defines can never
//! disagree about which one gets picked up.
//!
//! Defining one name in both layouts at once is
//! [`LoadError::ConflictingLayouts`] — an ambiguity worth naming
//! rather than resolving by a precedence rule nobody would remember.
//! (`mfile::File::from_dir` refuses the analogous `minimal.toml` /
//! `.minimal/minimal.toml` pair for the same reason.)
//!
//! A file may still carry the vestigial `name` field. It no longer
//! names anything: loading warns that the field isn't required and
//! drops it, taking the name from the filesystem either way. That is a
//! warning rather than an error so an older loadout keeps working
//! untouched.
//!
//! [`Source::loadout_dir`]: crate::core::source::Source::loadout_dir

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::core::loadout::{Loadout, LoadoutFile, LoadoutName};

/// The filename a [`Layout::Directory`] loadout is defined in, inside
/// the directory named after it.
pub const LOADOUT_FILE_NAME: &str = "loadout.toml";

/// Which on-disk shape a loadout was found in.
///
/// Carried on [`LoadoutEntry`] and returned by [`load_loadout`] so a
/// caller can report where a loadout actually came from. Nothing
/// downstream branches on it: the two layouts differ only in path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `<loadouts>/<name>.toml` — a loadout that is just a file.
    Flat,
    /// `<loadouts>/<name>/loadout.toml` — the definition inside the
    /// loadout's own directory, so the whole loadout is one
    /// self-contained tree that can be a git checkout.
    Directory,
}

impl Layout {
    /// The path this layout puts loadout `name` at, under the loadouts
    /// directory `dir`.
    ///
    /// `name` is a [`LoadoutName`], which is validated as a single
    /// path component that stays put — no separators, no NUL, and
    /// neither `.` nor `..` — so both joins land directly under `dir`.
    /// Taking a `LoadoutName` rather than a `&str` is what makes that
    /// a type-level guarantee instead of a caller's obligation.
    #[must_use]
    pub fn path_for(self, dir: &Path, name: &LoadoutName) -> PathBuf {
        match self {
            Self::Flat => dir.join(format!("{name}.toml")),
            Self::Directory => dir.join(name.as_ref()).join(LOADOUT_FILE_NAME),
        }
    }
}

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
    /// The name taken from the filesystem — the filename stem under
    /// [`Layout::Flat`], the directory name under
    /// [`Layout::Directory`] — isn't a valid loadout name (e.g.
    /// contains a path separator or NUL). Caught before parsing the
    /// TOML so the operator gets the concrete "your filename is bad"
    /// message instead of a downstream one about the contents.
    #[error("loadout file `{path}` has an invalid stem: {source}")]
    InvalidStem {
        path: PathBuf,
        #[source]
        source: crate::core::loadout::LoadoutNameError,
    },
    /// One name defined in both layouts at once. Refused rather than
    /// resolved by precedence: whichever file lost would go on looking
    /// live while having no effect, which is the failure mode a
    /// half-finished migration produces and the hardest one to spot.
    #[error("loadout `{name}` is defined twice:\n  {}\n  {}\nremove one.", flat.display(), directory.display())]
    ConflictingLayouts {
        name: String,
        flat: PathBuf,
        directory: PathBuf,
    },
    /// No loadout by this name in either layout.
    ///
    /// Distinct from [`LoadError::Io`] so a caller can treat absence
    /// as a normal outcome — the zero-config fallback in the `min` CLI
    /// does exactly that — and so the message can name every path that
    /// was tried instead of just the last one.
    #[error("no loadout `{name}` in `{}` (looked for `{name}.toml` and `{name}/{LOADOUT_FILE_NAME}`)", dir.display())]
    NotFound {
        name: String,
        dir: PathBuf,
        /// The candidate paths stat'd, in probe order. Carried for
        /// callers that want to list them; the `Display` above
        /// summarizes them in the shape the user would type.
        tried: Vec<PathBuf>,
    },
}

/// An entry produced by [`list_loadouts`]: the name this loadout was
/// found under, and either the parsed [`Loadout`] or the error that
/// prevented parsing.
#[derive(Debug)]
#[non_exhaustive]
pub struct LoadoutEntry {
    /// The name taken from the filesystem — the filename stem under
    /// [`Layout::Flat`], the directory name under
    /// [`Layout::Directory`]. This is what the user interacts with as
    /// the loadout identifier, and what the parsed loadout is named
    /// after.
    pub name: String,
    /// Which layout this entry was found in.
    pub layout: Layout,
    /// Path to the loadout file itself — `<name>.toml` or
    /// `<name>/loadout.toml`, not the directory. Absolute when
    /// `list_loadouts` canonicalized the input directory (its normal
    /// path); may be relative if the caller invoked
    /// [`read_loadout_file`] directly with a relative argument.
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

/// Parse a [`Layout::Flat`] loadout — `<loadouts>/<name>.toml` — and
/// name it after its filename stem, which must be a valid
/// [`LoadoutName`] (rejects path separators, NUL, empty).
///
/// For the directory layout, see [`read_loadout_dir`]; to resolve a
/// name across both, [`load_loadout`].
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
    let name = LoadoutName::try_new(file_stem_str).map_err(|source| LoadError::InvalidStem {
        path: path.to_path_buf(),
        source,
    })?;
    parse_named(path, &name)
}

/// Parse a [`Layout::Directory`] loadout — read `dir/loadout.toml` and
/// name it after `dir` itself, which must be a valid [`LoadoutName`].
///
/// The counterpart to [`read_loadout_file`]. They are separate
/// functions rather than one that sniffs the filename because a flat
/// loadout may legitimately *be* named `loadout`: sniffing would name
/// `<loadouts>/loadout.toml` after its parent directory (`loadouts`)
/// instead of after its stem. Which layout a path is in is knowledge
/// the caller has and the path alone does not.
///
/// # Errors
///
/// See [`LoadError`]. A `dir` with no `loadout.toml` in it is
/// [`LoadError::Io`] with an ENOENT source; [`load_loadout`] probes
/// for the file before calling here, so it reports absence as
/// [`LoadError::NotFound`] instead.
pub fn read_loadout_dir(dir: &Path) -> Result<Loadout, LoadError> {
    let path = dir.join(LOADOUT_FILE_NAME);
    // As in `read_loadout_file`: the name is validated before the read
    // so a bad one is reported as such. The `InvalidStem` path is
    // named for `dir`, not the file inside it — `dir` is the part the
    // operator would rename.
    let dir_name = dir.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    let name = LoadoutName::try_new(dir_name).map_err(|source| LoadError::InvalidStem {
        path: dir.to_path_buf(),
        source,
    })?;
    parse_named(&path, &name)
}

/// Read and parse the loadout file at `path`, naming it `name`.
///
/// The shared tail of [`read_loadout_file`] and [`read_loadout_dir`];
/// they differ only in where the name comes from.
fn parse_named(path: &Path, name: &LoadoutName) -> Result<Loadout, LoadError> {
    let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file: LoadoutFile = toml::from_str(&contents).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    match DeclaredName::classify(file.declared_name(), name) {
        DeclaredName::Absent => {}
        DeclaredName::Redundant => tracing::warn!(
            path = %path.display(),
            loadout = %name,
            "loadout `{name}` declares a `name` field; a loadout is now named \
             after its file, so the field is no longer required and can be deleted",
        ),
        DeclaredName::Mismatched(declared) => tracing::warn!(
            path = %path.display(),
            loadout = %name,
            declared_name = %declared,
            "loadout `{name}` declares the name `{declared}`, which does not match \
             its filename; a loadout is now named after its file, so the field is no \
             longer required — using `{name}` and ignoring the declared name",
        ),
    }

    Ok(file.into_loadout(name.clone()))
}

/// Resolve one loadout by name under the loadouts directory `dir`,
/// across both layouts.
///
/// The single name → loadout path in the codebase: callers name a
/// loadout, this decides which file that is. Probing both layouts here
/// rather than at each call site is what keeps "which layouts exist"
/// one fact rather than several.
///
/// Both layouts defining `name` is [`LoadError::ConflictingLayouts`],
/// refused rather than resolved by precedence — see the module docs.
///
/// # Errors
///
/// [`LoadError::NotFound`] when neither layout has it; otherwise see
/// [`LoadError`].
pub fn load_loadout(dir: &Path, name: &LoadoutName) -> Result<(Loadout, Layout), LoadError> {
    let flat = Layout::Flat.path_for(dir, name);
    let directory = Layout::Directory.path_for(dir, name);

    // `exists()` follows symlinks, deliberately: a symlinked
    // `dev.toml` is a loadout the user pointed at something, and the
    // read below is what would fail if the target is gone. This is
    // only choosing which path to read.
    match (flat.exists(), directory.exists()) {
        (true, true) => Err(LoadError::ConflictingLayouts {
            name: name.as_ref().to_owned(),
            flat,
            directory,
        }),
        (true, false) => read_loadout_file(&flat).map(|l| (l, Layout::Flat)),
        // `read_loadout_dir` takes the loadout's directory, not the
        // file inside it — that is where it reads the name from.
        (false, true) => read_loadout_dir(&dir.join(name.as_ref())).map(|l| (l, Layout::Directory)),
        (false, false) => Err(LoadError::NotFound {
            name: name.as_ref().to_owned(),
            dir: dir.to_path_buf(),
            tried: vec![flat, directory],
        }),
    }
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

/// Enumerate every loadout in `dir`, in both layouts, and try to parse
/// each. Returns one [`LoadoutEntry`] per loadout **name**, sorted by
/// name; parse failures are folded into the entry's `loadout` field so
/// the caller can surface them in the listing rather than aborting the
/// whole scan.
///
/// Picked up: `*.toml` files ([`Layout::Flat`]) and subdirectories
/// containing a `loadout.toml` ([`Layout::Directory`]). A name found
/// in both yields a single entry carrying
/// [`LoadError::ConflictingLayouts`], so a conflict surfaces here the
/// same way a parse failure does.
///
/// Everything else is silently ignored — in particular a subdirectory
/// with no `loadout.toml`, which is the asset directory a flat
/// `<name>.toml` anchors its `$LOADOUT_ROOT` patches and hook scripts
/// at.
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

    // Keyed by name, not by path: the two layouts are two ways of
    // spelling the same identifier, so a name is one entry however
    // many files claim it. `BTreeMap` also gives the name ordering the
    // listing wants for free, across both layouts at once.
    let mut found: BTreeMap<String, LoadoutEntry> = BTreeMap::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
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
                continue;
            }
        };
        let path = entry.path();
        let Some((name, layout, file)) = classify_dirent(&path) else {
            continue;
        };
        match found.entry(name.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                let loadout = match layout {
                    Layout::Flat => read_loadout_file(&file),
                    Layout::Directory => read_loadout_dir(&path),
                };
                slot.insert(LoadoutEntry {
                    name,
                    layout,
                    path: file,
                    loadout,
                });
            }
            // Second sighting of a name: the other layout has it too.
            // Whatever arrived first is replaced by the conflict, so
            // the listing reports the ambiguity instead of a loadout
            // that may not be the one in effect.
            //
            // The entry is pinned to the flat form rather than to
            // whichever dirent happened to come second — `read_dir`
            // order is not defined, and an entry whose `layout` and
            // `path` flipped run to run would be a listing that
            // changed without the directory changing. Both paths are
            // in the error either way, which is where a conflicting
            // entry's real information lives.
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let existing = slot.get().path.clone();
                let (flat, directory) = match layout {
                    Layout::Flat => (file, existing),
                    Layout::Directory => (existing, file),
                };
                let entry = slot.get_mut();
                entry.layout = Layout::Flat;
                entry.path.clone_from(&flat);
                entry.loadout = Err(LoadError::ConflictingLayouts {
                    name: entry.name.clone(),
                    flat,
                    directory,
                });
            }
        }
    }
    Ok(found.into_values().collect())
}

/// Classify one entry of the loadouts directory into
/// `(name, layout, loadout file path)`, or `None` for something that
/// isn't a loadout at all.
///
/// The path is taken as given rather than stat'd via the [`DirEntry`]
/// so `is_file` / `is_dir` follow symlinks — a symlinked `dev.toml`
/// or a symlinked `dev/` still lists. (Whether a symlinked loadout
/// *directory* can anchor hook scripts is a separate question, and
/// `hookscripts::resolve_under_anchor` answers it: it cannot.)
///
/// [`DirEntry`]: std::fs::DirEntry
fn classify_dirent(path: &Path) -> Option<(String, Layout, PathBuf)> {
    if path.is_dir() {
        let file = path.join(LOADOUT_FILE_NAME);
        // A directory without one is not a loadout: it is the asset
        // directory beside a flat `<name>.toml`.
        if !file.is_file() {
            return None;
        }
        let name = path.file_name().and_then(|s| s.to_str())?.to_string();
        return Some((name, Layout::Directory, file));
    }
    if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("toml") {
        return None;
    }
    let name = path.file_stem().and_then(|s| s.to_str())?.to_string();
    Some((name, Layout::Flat, path.to_path_buf()))
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

    /// Lay out a [`Layout::Directory`] loadout: `<dir>/<name>/loadout.toml`.
    fn write_dir_loadout(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let root = dir.join(name);
        std::fs::create_dir_all(&root).unwrap();
        write_file(&root, LOADOUT_FILE_NAME, contents)
    }

    fn name(s: &str) -> LoadoutName {
        LoadoutName::try_new(s).unwrap()
    }

    /// The tempdir root as [`list_loadouts`] will report it.
    ///
    /// That function canonicalizes its input so every reported path is
    /// absolute, which on macOS rewrites `/var/…` to `/private/var/…`.
    /// An expectation built from the raw `TempDir` path would compare
    /// the symlinked form against the resolved one and fail there
    /// while passing on Linux. Tests of [`load_loadout`] don't need
    /// this — it takes the directory as given.
    fn listed_root(dir: &TempDir) -> PathBuf {
        std::fs::canonicalize(dir.path()).unwrap()
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

    /// `list_loadouts` enumerates both layouts in name order, ignores
    /// non-`.toml` entries and directories that hold no
    /// `loadout.toml`, and folds per-entry errors into the returned
    /// list rather than aborting.
    #[test]
    fn list_loadouts_enumerates_and_sorts() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "beta.toml", r#"packages = ["zellij"]"#);
        write_file(dir.path(), "alpha.toml", r#"packages = ["helix"]"#);
        write_file(dir.path(), "readme.txt", "not a loadout");
        // A directory-layout loadout sorts in among the flat ones by
        // name, with no marker of which layout it came from beyond
        // `LoadoutEntry::layout`.
        write_dir_loadout(dir.path(), "gamma", r#"packages = ["fish"]"#);
        // A bare subdirectory is not a loadout — it is the asset
        // directory a flat `<name>.toml` anchors `$LOADOUT_ROOT` at.
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        // Malformed but present — should show up as an entry with
        // a `Parse` error, not skip the file entirely.
        write_file(dir.path(), "broken.toml", "= bad =");
        // A stale `name` field is no longer a failure: the entry
        // parses and is listed under its filename.
        write_file(dir.path(), "renamed.toml", r#"name = "different""#);

        let entries = list_loadouts(dir.path()).expect("should list");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["alpha", "beta", "broken", "gamma", "renamed"],
            "both layouts list, in one name order; `nested` and `readme.txt` do not",
        );

        assert!(entries[0].loadout.is_ok());
        assert_eq!(entries[0].layout, Layout::Flat);
        assert!(entries[1].loadout.is_ok());
        assert!(matches!(entries[2].loadout, Err(LoadError::Parse { .. })));

        let gamma = &entries[3];
        assert_eq!(gamma.layout, Layout::Directory);
        assert_eq!(
            gamma.path,
            listed_root(&dir).join("gamma").join(LOADOUT_FILE_NAME)
        );
        assert_eq!(
            gamma.loadout.as_ref().expect("gamma").packages(),
            &["fish"],
            "a directory loadout is named after its directory",
        );
        assert_eq!(
            gamma.loadout.as_ref().expect("gamma").name().as_ref(),
            "gamma"
        );

        assert_eq!(
            entries[4]
                .loadout
                .as_ref()
                .expect("renamed")
                .name()
                .as_ref(),
            "renamed"
        );
    }

    /// One name in both layouts lists as a *single* entry carrying the
    /// conflict, not as two rows or as a silent precedence win. The
    /// caller (`min loadout list`) already routes an `Err` entry to
    /// stderr and a non-zero exit, so this is all the reporting the
    /// ambiguity needs.
    #[test]
    fn list_loadouts_reports_a_name_in_both_layouts_once() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "dev.toml", r#"packages = ["helix"]"#);
        write_dir_loadout(dir.path(), "dev", r#"packages = ["zellij"]"#);
        write_file(dir.path(), "ok.toml", "");

        let entries = list_loadouts(dir.path()).expect("should list");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["dev", "ok"], "one entry per name");

        let Err(LoadError::ConflictingLayouts {
            name,
            flat,
            directory,
        }) = &entries[0].loadout
        else {
            panic!("expected a conflict, got: {:?}", entries[0].loadout);
        };
        let root = listed_root(&dir);
        assert_eq!(name, "dev");
        assert_eq!(flat, &root.join("dev.toml"));
        assert_eq!(directory, &root.join("dev").join(LOADOUT_FILE_NAME));
        // Unaffected neighbours still load.
        assert!(entries[1].loadout.is_ok());
    }

    /// A missing directory returns `NotFound`, not a generic I/O error.
    #[test]
    fn list_loadouts_missing_dir_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");
        let err = list_loadouts(&missing).expect_err("missing dir should error");
        assert!(matches!(err, ListError::NotFound { .. }));
    }

    // ---- the directory layout ----

    /// A directory-layout loadout is named after its *directory*, and
    /// the `loadout.toml` inside it needs no `name` field.
    #[test]
    fn read_loadout_dir_names_from_the_directory() {
        let dir = TempDir::new().unwrap();
        write_dir_loadout(dir.path(), "dev", r#"packages = ["helix"]"#);
        let loadout = read_loadout_dir(&dir.path().join("dev")).expect("should load");
        assert_eq!(loadout.name().as_ref(), "dev");
        assert_eq!(loadout.packages(), &["helix"]);
    }

    /// The two layouts describe the same loadout: same name, same
    /// contents, whichever shape it is filed in.
    #[test]
    fn load_loadout_resolves_either_layout() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "flat.toml", r#"packages = ["helix"]"#);
        write_dir_loadout(dir.path(), "vc", r#"packages = ["helix"]"#);

        let (flat, layout) = load_loadout(dir.path(), &name("flat")).expect("flat");
        assert_eq!(layout, Layout::Flat);
        assert_eq!(flat.name().as_ref(), "flat");

        let (vc, layout) = load_loadout(dir.path(), &name("vc")).expect("directory");
        assert_eq!(layout, Layout::Directory);
        assert_eq!(vc.name().as_ref(), "vc");
        assert_eq!(vc.packages(), flat.packages());
    }

    /// Both layouts at once is refused by name, naming both files —
    /// the ambiguity is reported, never resolved by precedence.
    #[test]
    fn load_loadout_refuses_a_name_in_both_layouts() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "dev.toml", "");
        write_dir_loadout(dir.path(), "dev", "");

        let err = load_loadout(dir.path(), &name("dev")).expect_err("ambiguous");
        assert!(matches!(err, LoadError::ConflictingLayouts { .. }));
        // The message has to name both files: "remove one" is only
        // actionable if the user knows which two.
        let msg = err.to_string();
        assert!(msg.contains("dev.toml"), "got: {msg}");
        assert!(msg.contains(LOADOUT_FILE_NAME), "got: {msg}");
    }

    /// Absence is its own variant, not an I/O error, and names both
    /// paths that were tried.
    #[test]
    fn load_loadout_missing_names_both_candidates() {
        let dir = TempDir::new().unwrap();
        let err = load_loadout(dir.path(), &name("nope")).expect_err("missing");
        let LoadError::NotFound { tried, .. } = &err else {
            panic!("expected NotFound, got: {err:?}");
        };
        assert_eq!(
            tried,
            &[
                dir.path().join("nope.toml"),
                dir.path().join("nope").join(LOADOUT_FILE_NAME),
            ]
        );
        let msg = err.to_string();
        assert!(msg.contains("nope.toml"), "got: {msg}");
        assert!(msg.contains("nope/loadout.toml"), "got: {msg}");
    }

    /// A bare `<name>/` with no `loadout.toml` is not a loadout: that
    /// is the asset directory a flat `<name>.toml` anchors its
    /// `$LOADOUT_ROOT` patches and hook scripts at, and it must keep
    /// resolving to the flat file beside it.
    #[test]
    fn an_asset_directory_beside_a_flat_loadout_is_not_a_conflict() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "dev.toml", r#"packages = ["helix"]"#);
        std::fs::create_dir(dir.path().join("dev")).unwrap();
        write_file(&dir.path().join("dev"), "config.toml", "theme = 'nord'");

        let (loadout, layout) = load_loadout(dir.path(), &name("dev")).expect("flat still wins");
        assert_eq!(layout, Layout::Flat);
        assert_eq!(loadout.packages(), &["helix"]);
    }

    /// A flat loadout may legitimately be *named* `loadout`, so
    /// `<loadouts>/loadout.toml` is the loadout `loadout` — not a
    /// directory-layout file misread as being named after the
    /// loadouts directory itself. This is why the two layouts have
    /// separate readers rather than one that sniffs the filename.
    #[test]
    fn a_flat_loadout_named_loadout_is_named_after_its_stem() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), LOADOUT_FILE_NAME, r#"packages = ["helix"]"#);

        let (loadout, layout) = load_loadout(dir.path(), &name("loadout")).expect("should load");
        assert_eq!(layout, Layout::Flat);
        assert_eq!(loadout.name().as_ref(), "loadout");

        let entries = list_loadouts(dir.path()).expect("should list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "loadout");
        assert_eq!(entries[0].layout, Layout::Flat);
    }

    /// `Layout::path_for` is the one place a name becomes a path;
    /// both shapes stay a single component under the loadouts dir.
    #[test]
    fn layout_path_for_spells_both_shapes() {
        let dir = Path::new("/cfg/minimal/loadouts");
        assert_eq!(
            Layout::Flat.path_for(dir, &name("dev")),
            PathBuf::from("/cfg/minimal/loadouts/dev.toml")
        );
        assert_eq!(
            Layout::Directory.path_for(dir, &name("dev")),
            PathBuf::from("/cfg/minimal/loadouts/dev/loadout.toml")
        );
    }
}
