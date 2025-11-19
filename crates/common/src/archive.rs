//! Common code for working with archives.

use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;
use std::path::{Path, StripPrefixError};

const ZSTD_LEVEL: i32 = 5;

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
pub fn compress_dir<P: AsRef<Path>>(
    dir: P,
    override_level: Option<i32>,
) -> Result<(std::fs::File, [u8; 32]), std::io::Error> {
    let mut tar_file = tempfile::tempfile()?;
    let mut hasher = Sha256::new();
    {
        let mut w = super::Tee::new(&mut tar_file, &mut hasher);
        let encoder = zstd::stream::Encoder::new(&mut w, override_level.unwrap_or(ZSTD_LEVEL))?;
        let mut tar_builder = tar::Builder::new(encoder);
        tar_builder.mode(tar::HeaderMode::Deterministic);
        tar_builder.follow_symlinks(false);
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
        if path.ends_with(".tar.gz") || path.ends_with(".tgz") {
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
            let p = entry.path()?;
            if p.as_ref().as_os_str() == "pax_global_header" {
                continue;
            }
            let path = p.strip_prefix(prefix)?.to_owned();
            entry.unpack(dest_dir.join(path))?;
        }
    } else {
        archive.unpack(dest_dir)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_from_extension() {
        assert!(matches!(
            Compression::from_extension("file.tar.gz"),
            Some(Compression::Gzip)
        ));
        assert!(matches!(
            Compression::from_extension("file.tar.xz"),
            Some(Compression::Xz)
        ));
        assert!(matches!(
            Compression::from_extension("file.tar.zst"),
            Some(Compression::Zstd)
        ));
        assert!(matches!(
            Compression::from_extension("file.tar"),
            Some(Compression::None)
        ));
        assert!(Compression::from_extension("file.zip").is_none());
        assert!(Compression::from_extension("file.txt").is_none());
    }

    #[test]
    fn extract_uncompressed_tar() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // Create a simple tar archive in memory
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            // Add a file
            let content = b"Hello, World!";
            let mut header = tar::Header::new_gnu();
            header.set_path("test.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();

            builder.finish().unwrap();
        }

        // Extract the tar
        extract_compressed_tar(&tar_data[..], Compression::None, extract_dir.path(), None)?;

        // Verify the extracted file
        let extracted_path = extract_dir.path().join("test.txt");
        assert!(extracted_path.exists());
        let contents = std::fs::read_to_string(extracted_path).unwrap();
        assert_eq!(contents, "Hello, World!");

        Ok(())
    }

    #[test]
    fn extract_with_prefix() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // Create a tar archive with a prefix directory
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            // Add directory entries
            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_path("prefix/").unwrap();
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_cksum();
            builder.append(&dir_header, &[][..]).unwrap();

            let mut subdir_header = tar::Header::new_gnu();
            subdir_header.set_path("prefix/subdir/").unwrap();
            subdir_header.set_size(0);
            subdir_header.set_mode(0o755);
            subdir_header.set_entry_type(tar::EntryType::Directory);
            subdir_header.set_cksum();
            builder.append(&subdir_header, &[][..]).unwrap();

            // Add file
            let content = b"Test content";
            let mut header = tar::Header::new_gnu();
            header.set_path("prefix/subdir/file.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();

            builder.finish().unwrap();
        }

        // Extract with prefix stripping
        extract_compressed_tar(
            &tar_data[..],
            Compression::None,
            extract_dir.path(),
            Some(&"prefix".to_string()),
        )?;

        // Verify the file was extracted without the prefix
        let extracted_path = extract_dir.path().join("subdir/file.txt");
        assert!(extracted_path.exists());
        let contents = std::fs::read_to_string(extracted_path).unwrap();
        assert_eq!(contents, "Test content");

        // Verify the prefix directory doesn't exist
        assert!(!extract_dir.path().join("prefix").exists());

        Ok(())
    }

    #[test]
    fn extract_gzip_tar() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // Create a gzipped tar archive
        let mut compressed_data = Vec::new();
        {
            let encoder =
                flate2::write::GzEncoder::new(&mut compressed_data, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);

            let content = b"Compressed content";
            let mut header = tar::Header::new_gnu();
            header.set_path("compressed.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();

            builder.into_inner().unwrap().finish().unwrap();
        }

        // Extract the gzipped tar
        extract_compressed_tar(
            &compressed_data[..],
            Compression::Gzip,
            extract_dir.path(),
            None,
        )?;

        // Verify extraction
        let extracted_path = extract_dir.path().join("compressed.txt");
        assert!(extracted_path.exists());
        let contents = std::fs::read_to_string(extracted_path).unwrap();
        assert_eq!(contents, "Compressed content");

        Ok(())
    }

    #[test]
    fn compress_dir() -> std::io::Result<()> {
        let temp_dir = tempfile::tempdir()?;

        // Create some test files
        std::fs::write(temp_dir.path().join("file1.txt"), b"Content 1")?;
        std::fs::create_dir(temp_dir.path().join("subdir"))?;
        std::fs::write(temp_dir.path().join("subdir/file2.txt"), b"Content 2")?;

        // Compress the directory
        let (mut compressed_file, hash) = super::compress_dir(temp_dir.path(), None)?;

        // Verify we got a hash
        assert_eq!(hash.len(), 32);

        // Verify we can read the compressed data
        let mut buffer = Vec::new();
        compressed_file.read_to_end(&mut buffer)?;
        assert!(!buffer.is_empty());

        Ok(())
    }
}
