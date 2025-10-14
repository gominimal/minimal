//! Common types and utilities used across the minimal codebase.

pub mod fetchers;
pub mod target;
pub use target::Target;

pub mod archive;

mod spec_hash;
pub use spec_hash::SpecHash;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tracing::warn;

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
#[derive(Debug, thiserror::Error)]
pub enum HardlinkError {
    #[error("IO error: {0}")]
    IO(&'static str, PathBuf, std::io::Error),
    #[error("Hardlink error: {0}")]
    HardlinkFailed(PathBuf, PathBuf, std::io::Error),
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
            symlink(&target, &dst_path)
                .map_err(|e| HardlinkError::IO("create symlink", dst_path, e))?;
        }
    }

    Ok(())
}
