//! Common types and utilities used across the minimal codebase.

pub mod fetchers;

mod spec_hash;
use sha2::{Digest, Sha256};
pub use spec_hash::SpecHash;
use std::{
    fs::File,
    io::{self, Seek, Write},
    path::Path,
};

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

/// Compresses files in the given directory into a .tar.zst, returning the compressed file + its sha256.
pub fn compress_dir<P: AsRef<Path>>(dir: P) -> Result<(File, [u8; 32]), io::Error> {
    let mut tar_file = tempfile::tempfile()?;
    let mut hasher = Sha256::new();
    {
        let mut w = Tee::new(&mut tar_file, &mut hasher);
        let encoder = zstd::stream::Encoder::new(&mut w, 3)?;
        let mut tar_builder = tar::Builder::new(encoder);
        tar_builder.append_dir_all(".", dir)?;
        tar_builder.into_inner()?.finish()?;
    }
    tar_file.seek(std::io::SeekFrom::Start(0))?;

    Ok((tar_file, hasher.finalize().into()))
}
