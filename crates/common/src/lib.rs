//! Common types and utilities used across the minimal codebase.

pub mod archive;
pub mod fetchers;
pub mod mfile;

pub mod repo_spec;
mod spec_hash;
pub use spec_hash::SpecHash;
mod subsets;
pub use subsets::SubsetSpec;
pub mod target;
pub use target::Target;

use std::{
    env, fmt,
    io::Write,
    path::{Path, PathBuf},
};
use tracing::warn;

/// Describes where a build-spec came from.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SpecOrigin {
    /// Filetree of nickel came from a path on the filesystem, not necessarily under VCS.
    LocalDir { given: PathBuf, absolute: PathBuf },
    /// Filetree came from a checkout of a VCS repo.
    Repo(repo_spec::Repo),
    /// Nickel was given inline and cannot be attributed to somewhere - usually for tests.
    #[default]
    Inline,
}

impl SpecOrigin {
    /// Constructs a [SpecOrigin] from the given directory on the system. Do not use this
    /// if the directory represents a checked-out pristine repo, for that case,
    /// use [SpecOrigin::Repo] instead.
    pub fn from_dir<P: AsRef<Path>>(p: P) -> Self {
        let p = p.as_ref();
        match p.is_absolute() {
            true => SpecOrigin::LocalDir {
                given: p.to_path_buf(),
                absolute: p.to_path_buf(),
            },
            false => SpecOrigin::LocalDir {
                given: p.to_path_buf(),
                absolute: env::current_dir().unwrap().join(p).canonicalize().unwrap(),
            },
        }
    }
}

/// Implements [Write], mirroring all writes to two underlying writers.
#[derive(Debug)]
pub struct Tee<W1: Write, W2: Write> {
    writer1: W1,
    writer2: W2,
}

impl<W1: Write, W2: Write> Tee<W1, W2> {
    /// Creates a new tee, where all writes are mirrorred to both given writers.
    pub fn new(writer1: W1, writer2: W2) -> Self {
        Tee { writer1, writer2 }
    }
}

impl<W1: Write, W2: Write> Write for Tee<W1, W2> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer1.write_all(buf)?;
        self.writer2.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer1.flush()?;
        self.writer2.flush()?;
        Ok(())
    }
}

/// The error produced by calls to [hardlink_dir_contents].
#[derive(Debug)]
pub enum HardlinkError {
    IO(&'static str, PathBuf, std::io::Error),
    HardlinkFailed(PathBuf, PathBuf, std::io::Error),
}

impl fmt::Display for HardlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardlinkError::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            HardlinkError::HardlinkFailed(from, to, e) => write!(
                f,
                "failed to hardlink {} to {}: {}",
                from.display(),
                to.display(),
                e
            ),
        }
    }
}

impl std::error::Error for HardlinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HardlinkError::IO(_, _, e) => Some(e),
            HardlinkError::HardlinkFailed(_, _, e) => Some(e),
        }
    }
}

/// Creates a hardlink farm in dst representing files in src, recursively.
pub fn hardlink_dir_contents(src: &Path, dst: &Path) -> Result<(), HardlinkError> {
    use std::fs;

    for entry in
        fs::read_dir(src).map_err(|e| HardlinkError::IO("read directory", src.to_path_buf(), e))?
    {
        let entry =
            entry.map_err(|e| HardlinkError::IO("read directory entry", src.to_path_buf(), e))?;

        let path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        let metadata = entry
            .metadata()
            .map_err(|e| HardlinkError::IO("get metadata", path.to_path_buf(), e))?;

        if metadata.is_dir() {
            fs::create_dir_all(&dst_path)
                .map_err(|e| HardlinkError::IO("create directory", dst_path.clone(), e))?;
            hardlink_dir_contents(&path, &dst_path)?;
        } else if metadata.is_file() {
            match fs::hard_link(&path, &dst_path) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        warn!(
                            "Not linking {} => {}, already exists",
                            path.display(),
                            dst_path.display()
                        );
                        Ok(())
                    } else {
                        Err(e)
                    }
                }
            }
            .map_err(|e| HardlinkError::HardlinkFailed(path.to_path_buf(), dst_path, e))?;
        } else if metadata.is_symlink() {
            use std::os::unix::fs::symlink;

            let target = fs::read_link(&path)
                .map_err(|e| HardlinkError::IO("read symlink", path.to_path_buf(), e))?;
            match symlink(&target, &dst_path) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        warn!(
                            "Not symlinking {} => {}, already exists",
                            path.display(),
                            dst_path.display()
                        );
                        Ok(())
                    } else {
                        Err(HardlinkError::IO("create symlink", dst_path, e))
                    }
                }
            }?;
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum GlobError {
    IO(std::io::Error),
    Glob(globset::Error),
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlobError::IO(e) => {
                write!(f, "I/O error: {}", e)
            }
            GlobError::Glob(e) => write!(f, "glob error: {}", e),
        }
    }
}

impl std::error::Error for GlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GlobError::IO(e) => Some(e),
            GlobError::Glob(e) => Some(e),
        }
    }
}

impl From<globset::Error> for GlobError {
    fn from(e: globset::Error) -> Self {
        GlobError::Glob(e)
    }
}

impl From<std::io::Error> for GlobError {
    fn from(e: std::io::Error) -> Self {
        GlobError::IO(e)
    }
}

/// Enumerates files which match the given glob within the given directory.
pub fn match_files_for_glob(dir: &Path, glob: &str) -> Result<Vec<PathBuf>, GlobError> {
    let mut results = Vec::new();

    let matcher = globset::GlobBuilder::new(glob)
        .literal_separator(true)
        .empty_alternates(true)
        .build()?
        .compile_matcher();

    // Walk the filesystem starting from root_dir
    fn walk_dir(
        dir: &Path,
        root_dir: &Path,
        matcher: &globset::GlobMatcher,
        results: &mut Vec<PathBuf>,
    ) -> Result<(), GlobError> {
        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;

            let path = entry.path();
            let subset = path.strip_prefix(root_dir).unwrap();
            if path.is_file() && matcher.is_match(subset) {
                results.push(path);
            } else if path.is_dir() {
                // Recursively walk subdirectories
                walk_dir(&path, root_dir, matcher, results)?;
            }
        }

        Ok(())
    }

    walk_dir(dir, dir, &matcher, &mut results)?;
    Ok(results)
}
