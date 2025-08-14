//! Abstraction over interactions with files/directories.

use path_absolutize::Absolutize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    File,
    Dir,
}

/// An error returned from the filesystem.
pub type FSError = std::io::Error;

/// The interface through which files can be interacted with.
pub trait FileSystem: std::fmt::Debug {
    type File: File;
    type DirEntry: DirEntry;
    type Subtree: FileSystem;

    fn open_read<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError>;
    fn open_write<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError>;

    fn mkdir<P: AsRef<Path>>(&self, path: P) -> Result<(), FSError>;
    fn read_dir<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Self::DirEntry>, FSError>;

    fn subtree<P: AsRef<Path>>(&self, path: P) -> Result<Self::Subtree, FSError>;
}

/// Describes the type representing some open file.
pub trait File: std::io::Read + std::io::Seek + std::io::Write {}

impl File for std::fs::File {}

/// Describes the type representing an entry in some directory.
pub trait DirEntry {
    fn path(&self) -> Result<PathBuf, FSError>;
    fn file_type(&self) -> Result<FileType, FSError>;
}

impl DirEntry for std::fs::DirEntry {
    fn path(&self) -> Result<PathBuf, FSError> {
        Ok(self.path())
    }
    fn file_type(&self) -> Result<FileType, FSError> {
        match self.file_type() {
            Err(e) => Err(e),
            Ok(ft) => Ok(if ft.is_file() {
                FileType::File
            } else if ft.is_dir() {
                FileType::Dir
            } else {
                unreachable!();
            }),
        }
    }
}

/// A [FileSystem] which exposes a directory and its children.
#[derive(Debug)]
pub struct LocalDir {
    base: PathBuf,
}

impl LocalDir {
    pub fn with_base<P: AsRef<Path>>(base: P) -> Result<Self, FSError> {
        Ok(Self {
            base: base.as_ref().to_path_buf().canonicalize()?,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.base.as_path()
    }

    fn extend<P: AsRef<Path>>(&self, extra: P) -> Result<Self, FSError> {
        if extra.as_ref().is_absolute() {
            return Err(std::io::Error::other("outside local dir"));
        }

        let mut base = self.base.clone();
        base.push(extra);

        Ok(Self {
            base: base.canonicalize()?,
        })
    }
}

impl FileSystem for LocalDir {
    type File = std::fs::File;
    type DirEntry = std::fs::DirEntry;
    type Subtree = Self;

    fn open_read<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError> {
        let p = Path::new(&self.base).join(path);
        let p = p.absolutize()?;
        if !p.starts_with(&self.base) {
            return Err(std::io::Error::other("outside local dir"));
        }

        Ok(std::fs::File::open(p.canonicalize()?)?)
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> Result<Self::File, FSError> {
        let p = Path::new(&self.base).join(path);
        let p = p.absolutize()?;
        if !p.starts_with(&self.base) {
            return Err(std::io::Error::other("outside local dir"));
        }

        Ok(std::fs::File::create(p)?)
    }

    fn read_dir<P: AsRef<Path>>(&self, _path: P) -> Result<Vec<Self::DirEntry>, FSError> {
        todo!();
    }

    fn mkdir<P: AsRef<Path>>(&self, path: P) -> Result<(), FSError> {
        let p = Path::new(&self.base).join(path);
        let p = p.absolutize()?;
        if !p.starts_with(&self.base) {
            return Err(std::io::Error::other("outside local dir"));
        }

        std::fs::create_dir(p)
    }

    fn subtree<P: AsRef<Path>>(&self, path: P) -> Result<Self::Subtree, FSError> {
        self.extend(path)
    }
}
