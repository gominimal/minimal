//! Common code for working with archives.

use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;
use std::path::{Path, StripPrefixError};

/// Errors which can occur when working with archives.
#[derive(Debug)]
pub enum ArchiveError {
    IO(std::io::Error),
    StripPrefix(StripPrefixError),
    CompressionError(String),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::IO(e) => write!(f, "I/O error: {}", e),
            ArchiveError::StripPrefix(e) => write!(f, "strip prefix error: {}", e),
            ArchiveError::CompressionError(s) => write!(f, "compression error: {}", s),
        }
    }
}

impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ArchiveError::IO(e) => Some(e),
            ArchiveError::StripPrefix(e) => Some(e),
            ArchiveError::CompressionError(_) => None,
        }
    }
}

impl From<StripPrefixError> for ArchiveError {
    fn from(spe: StripPrefixError) -> Self {
        Self::StripPrefix(spe)
    }
}

impl From<std::io::Error> for ArchiveError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<lzma_rs::error::Error> for ArchiveError {
    fn from(e: lzma_rs::error::Error) -> Self {
        match e {
            lzma_rs::error::Error::HeaderTooShort(e) | lzma_rs::error::Error::IoError(e) => {
                Self::IO(e)
            }
            lzma_rs::error::Error::LzmaError(s) | lzma_rs::error::Error::XzError(s) => {
                Self::CompressionError(s)
            }
        }
    }
}

/// Compresses files in the given directory into a .tar.zst, returning the compressed file + its sha256.
pub fn compress_dir<P: AsRef<Path>>(dir: P) -> Result<(std::fs::File, [u8; 32]), std::io::Error> {
    let mut tar_file = tempfile::tempfile()?;
    let mut hasher = Sha256::new();
    {
        let mut w = super::Tee::new(&mut tar_file, &mut hasher);
        let encoder = zstd::stream::Encoder::new(&mut w, 3)?;
        let mut tar_builder = tar::Builder::new(encoder);
        tar_builder.append_dir_all(".", dir)?;
        tar_builder.into_inner()?.finish()?;
    }
    use std::io::Seek;
    tar_file.seek(std::io::SeekFrom::Start(0))?;

    Ok((tar_file, hasher.finalize().into()))
}

/// Compression formats which can wrap a tarball.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
}

impl Compression {
    /// Detect compression format from file extension, if recognized.
    pub fn from_extension(path: &str) -> Option<Self> {
        if path.ends_with(".tar.gz") {
            Some(Compression::Gzip)
        } else if path.ends_with(".tar.xz") {
            Some(Compression::Xz)
        } else if path.ends_with(".tar.zst") {
            Some(Compression::Zstd)
        } else if path.ends_with(".tar") {
            Some(Compression::None)
        } else {
            None
        }
    }
}

/// Extracts the given compressed tarball to the given destination directory, given
/// decompression settings and any path to strip.
pub fn extract_compressed_tar<R: Read>(
    reader: R,
    compression: Compression,
    dest_dir: &Path,
    strip_prefix: Option<&String>,
) -> Result<(), ArchiveError> {
    match compression {
        Compression::None => extract_tar_impl(reader, dest_dir, strip_prefix),
        Compression::Gzip => {
            let decoder = flate2::read::GzDecoder::new(reader);
            extract_tar_impl(decoder, dest_dir, strip_prefix)
        }
        Compression::Zstd => {
            let decoder = zstd::Decoder::new(reader)?;
            extract_tar_impl(decoder, dest_dir, strip_prefix)
        }
        Compression::Xz => {
            let mut decomp_buf = tempfile::tempfile()?;
            lzma_rs::xz_decompress(&mut std::io::BufReader::new(reader), &mut decomp_buf)?;
            std::io::Seek::rewind(&mut decomp_buf)?;
            extract_tar_impl(decomp_buf, dest_dir, strip_prefix)
        }
    }
}

/// Extracts the tarball encoded in the given reader to the given directory,
/// stripping the given prefix.
fn extract_tar_impl<R: Read>(
    reader: R,
    dest_dir: &Path,
    strip_prefix: Option<&String>,
) -> Result<(), ArchiveError> {
    let mut archive = tar::Archive::new(reader);

    if let Some(prefix) = strip_prefix {
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.strip_prefix(prefix)?.to_owned();
            entry.unpack(dest_dir.join(path))?;
        }
    } else {
        archive.unpack(dest_dir)?;
    }

    Ok(())
}
