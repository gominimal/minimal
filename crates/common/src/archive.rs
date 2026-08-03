//! Common code for working with archives.

use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf, StripPrefixError};

const ZSTD_LEVEL: i32 = 5;

/// Cap on how many bytes an xz stream may decompress to before extraction.
///
/// Only the xz path needs this: it is the one compression arm that buffers the
/// entire decompressed tar to disk up front (see `extract_compressed_tar`).
/// Sized to clear real upstream source tarballs — the largest in common use
/// (LLVM, the kernel) land in the low single-digit GB uncompressed — while
/// still bounding a hostile stream. Matches the order of magnitude of
/// `MAX_PATCH_ENTRY_BYTES` / `MAX_UNPACK_INFLIGHT_BYTES` in `minimald::rpc`.
const MAX_XZ_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// A [`Write`] wrapper that stops accepting bytes past a cap.
///
/// Reports the overflow via [`Self::overflowed`] rather than only through the
/// `io::Error`, because `lzma_rs` wraps write errors in its own error type and
/// the distinction between "the stream was malformed" and "the stream was too
/// big" is worth keeping in the message the caller sees.
struct LimitedWriter<W> {
    inner: W,
    written: u64,
    max: u64,
    overflowed: bool,
}

impl<W: Write> LimitedWriter<W> {
    fn new(inner: W, max: u64) -> Self {
        Self {
            inner,
            written: 0,
            max,
            overflowed: false,
        }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.max.saturating_sub(self.written);
        if (buf.len() as u64) > remaining {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompressed output exceeds {} bytes", self.max),
            ));
        }
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Errors which can occur when working with archives.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArchiveError {
    IO(std::io::Error),
    StripPrefix(StripPrefixError),
    CompressionError(String),
    /// A tar entry's path resolved outside the destination directory. Carries
    /// the offending archive-relative path. (A symlink/hardlink whose *target*
    /// escapes is skipped with a warning instead — see `extract_tar_impl`.)
    PathTraversal(PathBuf),
    /// An xz stream decompressed past [`MAX_XZ_DECOMPRESSED_BYTES`].
    DecompressedTooLarge {
        /// The cap that was exceeded, in bytes.
        max: u64,
    },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::IO(e) => write!(f, "I/O error: {}", e),
            ArchiveError::StripPrefix(e) => write!(f, "strip prefix error: {}", e),
            ArchiveError::CompressionError(s) => write!(f, "compression error: {}", s),
            ArchiveError::PathTraversal(p) => {
                write!(
                    f,
                    "tar entry {} escapes the destination directory",
                    p.display()
                )
            }
            ArchiveError::DecompressedTooLarge { max } => {
                write!(f, "xz stream decompressed too large: over {max} bytes")
            }
        }
    }
}

impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ArchiveError::IO(e) => Some(e),
            ArchiveError::StripPrefix(e) => Some(e),
            ArchiveError::CompressionError(_) => None,
            ArchiveError::PathTraversal(_) => None,
            ArchiveError::DecompressedTooLarge { .. } => None,
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
    match_globs: &Option<globset::GlobSet>,
) -> Result<(std::fs::File, [u8; 32]), std::io::Error> {
    let mut tar_file = tempfile::tempfile()?;
    let mut hasher = super::HashWriter(Sha256::new());
    {
        let mut w = super::Tee::new(&mut tar_file, &mut hasher);
        let encoder = zstd::stream::Encoder::new(&mut w, override_level.unwrap_or(ZSTD_LEVEL))?;
        let mut tar_builder = tar::Builder::new(encoder);
        tar_builder.mode(tar::HeaderMode::Deterministic);
        tar_builder.follow_symlinks(false);
        add_dir_to_tar(&mut tar_builder, dir.as_ref(), ".", match_globs)?;
        tar_builder.into_inner()?.finish()?;
    }
    use std::io::Seek;
    tar_file.seek(std::io::SeekFrom::Start(0))?;

    Ok((tar_file, hasher.0.finalize().into()))
}

/// Recursively adds the specified directory to the given tarball.
///
/// Arguments:
///  * `tar_prefix` should be the "." or a prefix to prepend to all entries being written.
///  * `match_globs` if set, only file paths which match the glob will be written.
///
/// Entries are written in deterministic order, regardless of the iteration order of
/// the underlying filesystem.
pub fn add_dir_to_tar<W: Write>(
    tar: &mut tar::Builder<W>,
    src_dir: &Path,
    tar_prefix: &str,
    match_globs: &Option<globset::GlobSet>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(src_dir)?
        .map(|e| match e {
            Ok(e) => Ok((e.file_name(), e)),
            Err(e) => Err(e),
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, entry) in entries.into_iter() {
        let path = entry.path();
        let tar_path = if tar_prefix == "." {
            PathBuf::from(name)
        } else {
            PathBuf::from(tar_prefix).join(name)
        };

        if path.is_dir() {
            tar.append_dir(&tar_path, &path)?;
            add_dir_to_tar(tar, &path, &tar_path.to_string_lossy(), match_globs)?;
        } else {
            // For files, only include them if there were no specified matchers,
            // or something matched.
            let matched = match_globs
                .as_ref()
                .map(|gs| gs.is_match(&tar_path))
                .unwrap_or(true);
            if matched {
                tar.append_path_with_name(&path, &tar_path)?;
            }
        }
    }
    Ok(())
}

/// Compression formats which can wrap a tarball.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
    Bz2,
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
        } else if path.ends_with(".tar.bz2") {
            Some(Compression::Bz2)
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
            // The gzip/zstd/bz2 arms hand a streaming decoder straight to the
            // tar reader, so their disk use is bounded by what the tar
            // actually unpacks. `lzma_rs` exposes only a one-shot
            // `xz_decompress(reader, writer)`, so this arm has to materialize
            // the whole decompressed tar to a tempfile *before* extraction —
            // and before any entry has been validated. Uncapped, that makes a
            // few KB of hostile `.tar.xz` a disk-fill primitive. The cap turns
            // it into a clean error.
            let mut decomp_buf =
                LimitedWriter::new(tempfile::tempfile()?, MAX_XZ_DECOMPRESSED_BYTES);
            let res = lzma_rs::xz_decompress(&mut std::io::BufReader::new(reader), &mut decomp_buf);
            // Check the cap before the result: lzma_rs wraps our write error in
            // its own type, and were it ever to swallow one, proceeding would
            // extract a silently truncated tar.
            if decomp_buf.overflowed {
                return Err(ArchiveError::DecompressedTooLarge {
                    max: MAX_XZ_DECOMPRESSED_BYTES,
                });
            }
            res?;
            let mut decomp_buf = decomp_buf.into_inner();
            std::io::Seek::rewind(&mut decomp_buf)?;
            extract_tar_impl(decomp_buf, dest_dir, strip_prefix)
        }
        Compression::Bz2 => {
            let decoder = bzip2::read::BzDecoder::new(reader);
            extract_tar_impl(decoder, dest_dir, strip_prefix)
        }
    }
}

/// Lexically resolves `.` and `..` in a relative path without touching the
/// filesystem, returning `None` if the path is absolute or escapes its own
/// root (a `..` that would climb above the starting directory).
///
/// This is the containment gate for prefix-stripped tar extraction: unlike
/// [`Path::join`], it refuses entries and link targets that would resolve
/// outside `dest_dir`.
fn normalize_within_root(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => return None,
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    Some(out)
}

/// Extracts the tarball encoded in the given reader to the given directory,
/// stripping the given prefix.
fn extract_tar_impl<R: Read>(
    reader: R,
    dest_dir: &Path,
    strip_prefix: Option<&String>,
) -> Result<(), ArchiveError> {
    let mut archive = tar::Archive::new(reader);

    // Every archive goes through this loop, with or without a prefix to strip.
    // It used to be the `strip_prefix.is_some()` branch, with `None` handled by
    // a bare `Archive::unpack` — but that delegated link handling to `tar`,
    // which writes link targets verbatim, so an escaping symlink was rejected
    // with a prefix set and created without one. Same bytes, same threat,
    // opposite outcome; found by the `archive_extract` fuzz target. Callers
    // reach the `None` path with untrusted input (a package source that
    // declares no `strip_prefix`, remote-cache artifacts), so the checks below
    // have to cover it too.
    for entry in archive.entries()? {
        let mut entry = entry?;
        let p = entry.path()?;
        if p.as_ref().as_os_str() == "pax_global_header" {
            continue;
        }
        let stripped = match strip_prefix {
            Some(prefix) => p.strip_prefix(prefix)?.to_owned(),
            None => p.into_owned(),
        };

        // `Path::join` lets an entry named `../../x` (or an absolute path)
        // escape `dest_dir`, and `Entry::unpack` does not contain the write.
        // Reject any entry that resolves outside the destination tree before
        // touching the filesystem.
        let safe_path = normalize_within_root(&stripped)
            .ok_or_else(|| ArchiveError::PathTraversal(stripped.clone()))?;

        // A symlink/hardlink whose target escapes the tree would let a
        // subsequent entry be written through it to an arbitrary location
        // (target is relative to the link's own directory for a symlink,
        // to the destination root for a hardlink). SKIP such a link rather
        // than abort: never creating it defeats the write-through vector (a
        // later entry resolves to a contained regular path instead), while
        // legitimate upstream tarballs that ship escaping symlinks in test
        // fixtures (next.js, syft) still extract. The entry-path escape
        // above stays a hard error — a file writing to `../x` has no benign
        // form.
        let entry_type = entry.header().entry_type();
        // For a hardlink we must ALSO create the link ourselves (below): the
        // check here is necessary but not sufficient, because `Entry::unpack`
        // calls `fields.unpack(None, ..)`, and tar's `target_base: None` arm
        // uses the link name verbatim — resolving it against the **process
        // CWD**, not `dest_dir`. (`Archive::unpack` avoids this by routing
        // through `unpack_in`, which passes `Some(dst)` and validates.) So a
        // target like `etc/shadow` passes this check and then hardlinks the
        // real `/etc/shadow` into the destination, sharing the inode — an
        // escape no path-based containment can see. tar's own source comments
        // on exactly this asymmetry between symlinks and hardlinks.
        let mut hardlink_src: Option<PathBuf> = None;
        if (entry_type.is_symlink() || entry_type.is_hard_link())
            && let Some(target) = entry.link_name()?
        {
            let base = if entry_type.is_symlink() {
                safe_path.parent().unwrap_or_else(|| Path::new(""))
            } else {
                Path::new("")
            };
            match normalize_within_root(&base.join(target.as_ref())) {
                None => {
                    tracing::warn!(
                        entry = %stripped.display(),
                        target = %target.display(),
                        "skipping tar link whose target escapes the destination"
                    );
                    continue;
                }
                Some(normalized) if entry_type.is_hard_link() => {
                    hardlink_src = Some(normalized);
                }
                Some(_) => {}
            }
        }

        // Ensure any containing directory exists - most tarballs are good about ordering directory entries
        // ahead of files within them, but not all.
        if let Some(dirs) = safe_path.parent()
            && !dirs.as_os_str().is_empty()
        {
            let dir_path = dest_dir.join(dirs);
            if !std::fs::exists(&dir_path)? {
                std::fs::create_dir_all(dir_path)?;
            }
        }

        // Hardlinks: create explicitly, anchored to `dest_dir`, so the target
        // is the one we validated rather than a CWD-relative path. Mirrors
        // what `unpack_in`'s `target_base: Some(dst)` arm does.
        if let Some(rel_src) = hardlink_src {
            let link_src = dest_dir.join(&rel_src);
            match std::fs::hard_link(&link_src, dest_dir.join(&safe_path)) {
                Ok(()) => {}
                Err(e) => {
                    // Most often the target has not been extracted yet (or is
                    // absent from the archive). Skip, consistent with the
                    // escaping-link policy above: a missing link is benign,
                    // and aborting would reject tarballs that extract fine.
                    tracing::warn!(
                        entry = %stripped.display(),
                        target = %rel_src.display(),
                        error = %e,
                        "skipping tar hardlink that could not be created"
                    );
                }
            }
            continue;
        }

        if let tar::Unpacked::File(f) = entry.unpack(dest_dir.join(&safe_path))? {
            f.sync_all()?;
            drop(f);
        };
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
    fn extract_rejects_parent_dir_traversal() {
        let extract_dir = tempfile::tempdir().unwrap();

        // A malicious upstream tarball whose entry escapes the strip prefix.
        // The tar *writer* refuses a `..` path via `set_path`, so write the
        // header name field directly — exactly what a hand-crafted archive
        // (e.g. GNU tar `--absolute-names`) produces.
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let content = b"pwned";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            let name = b"prefix/../../evil.txt";
            header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();
            builder.finish().unwrap();
        }

        let err = extract_compressed_tar(
            &tar_data[..],
            Compression::None,
            extract_dir.path(),
            Some(&"prefix".to_string()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ArchiveError::PathTraversal(_)),
            "expected PathTraversal, got {err:?}"
        );
        // Nothing was written outside the destination.
        assert!(
            !extract_dir
                .path()
                .parent()
                .unwrap()
                .join("evil.txt")
                .exists()
        );
    }

    #[test]
    fn extract_skips_escaping_symlink() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // A symlink pointing outside the tree (as legit upstream test fixtures
        // ship). We SKIP it rather than abort the extraction, and the other
        // entries still land.
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_path("prefix/link").unwrap();
            link.set_link_name("../../../etc").unwrap();
            link.set_size(0);
            link.set_cksum();
            builder.append(&link, &[][..]).unwrap();

            let content = b"ok";
            let mut file = tar::Header::new_gnu();
            file.set_path("prefix/keep.txt").unwrap();
            file.set_size(content.len() as u64);
            file.set_cksum();
            builder.append(&file, &content[..]).unwrap();

            builder.finish().unwrap();
        }

        extract_compressed_tar(
            &tar_data[..],
            Compression::None,
            extract_dir.path(),
            Some(&"prefix".to_string()),
        )?;

        // The escaping symlink was skipped, not created (symlink_metadata sees
        // even a dangling link, so this is a real "does not exist" check).
        assert!(extract_dir.path().join("link").symlink_metadata().is_err());
        // The rest of the archive extracted fine.
        assert_eq!(
            std::fs::read_to_string(extract_dir.path().join("keep.txt")).unwrap(),
            "ok"
        );
        Ok(())
    }

    #[test]
    fn skipping_escaping_symlink_still_contains_write_through() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // The tar-slip vector: an escaping symlink followed by a write *through*
        // it. Because the link is skipped (never created), the follow-up write
        // resolves to a contained regular path under dest_dir — not `/etc`.
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_path("prefix/link").unwrap();
            link.set_link_name("../../../etc").unwrap();
            link.set_size(0);
            link.set_cksum();
            builder.append(&link, &[][..]).unwrap();

            let content = b"pwned";
            let mut file = tar::Header::new_gnu();
            file.set_path("prefix/link/passwd").unwrap();
            file.set_size(content.len() as u64);
            file.set_cksum();
            builder.append(&file, &content[..]).unwrap();

            builder.finish().unwrap();
        }

        extract_compressed_tar(
            &tar_data[..],
            Compression::None,
            extract_dir.path(),
            Some(&"prefix".to_string()),
        )?;

        // The write landed contained (dest/link/passwd), NOT through an escaping
        // symlink to some /etc/passwd outside the tree.
        assert_eq!(
            std::fs::read_to_string(extract_dir.path().join("link/passwd")).unwrap(),
            "pwned"
        );
        assert!(extract_dir.path().join("link").is_dir());
        Ok(())
    }

    /// Builds a tarball carrying an escaping symlink, and optionally a write
    /// *through* it. Entry paths are prefixed so the same bytes can be
    /// extracted with `strip_prefix: Some("prefix")` or with `None`.
    fn escaping_symlink_tar(write_through: bool) -> Vec<u8> {
        let mut tar_data = Vec::new();
        let mut builder = tar::Builder::new(&mut tar_data);

        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_path("prefix/link").unwrap();
        link.set_link_name("../../../etc").unwrap();
        link.set_size(0);
        link.set_cksum();
        builder.append(&link, &[][..]).unwrap();

        if write_through {
            let content = b"pwned";
            let mut file = tar::Header::new_gnu();
            file.set_path("prefix/link/passwd").unwrap();
            file.set_size(content.len() as u64);
            file.set_cksum();
            builder.append(&file, &content[..]).unwrap();
        }

        builder.finish().unwrap();
        drop(builder);
        tar_data
    }

    /// Regression: a hardlink entry must resolve against `dest_dir`, never the
    /// process CWD.
    ///
    /// `Entry::unpack` calls `fields.unpack(None, ..)`, and tar's
    /// `target_base: None` arm uses the link name verbatim — so a target like
    /// `etc/passwd` hardlinks the *real* file (relative to CWD) into the
    /// destination, sharing its inode. That is an escape no path-based
    /// containment can detect, because the resulting path really is inside the
    /// root. `Archive::unpack` never had this hole (it routes through
    /// `unpack_in`, which passes `Some(dst)`), so unifying both branches onto
    /// the per-entry loop is what exposed it.
    ///
    /// The fuzz oracle is structurally blind here too: it asserts *path*
    /// containment, and this escape has a contained path.
    #[test]
    fn extract_hardlink_does_not_escape_via_cwd() -> Result<(), ArchiveError> {
        use std::os::unix::fs::MetadataExt;

        // Deliberately does NOT touch the process CWD: `set_current_dir` is
        // global, and cargo runs tests on parallel threads in one process, so
        // mutating it would race every other test that uses a relative path.
        //
        // Instead use the CWD cargo already provides — the crate root — where
        // `Cargo.toml` is a real file reachable by a *relative* name. That is
        // precisely the daemon's situation: its CWD is `/`, so `etc/shadow` is
        // a live relative path from there.
        let victim = Path::new("Cargo.toml");
        assert!(
            victim.exists(),
            "expected cargo to run tests with CWD = crate root"
        );
        let victim_meta = std::fs::metadata(victim).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Link);
            link.set_path("loot").unwrap();
            // Normalizes cleanly, so the containment check passes it. The
            // danger is entirely in what it gets resolved *against*.
            link.set_link_name("Cargo.toml").unwrap();
            link.set_size(0);
            link.set_cksum();
            builder.append(&link, &[][..]).unwrap();
            builder.finish().unwrap();
        }

        let extract_dir = tempfile::tempdir().unwrap();
        extract_compressed_tar(&tar_data[..], Compression::None, extract_dir.path(), None)?;

        // Assert through the INODE, not the contents: a hardlink escape has a
        // perfectly contained path, so only identity distinguishes it. No
        // `unwrap_or_default()` — a read failure must not read as success.
        let loot = extract_dir.path().join("loot");
        if let Ok(loot_meta) = std::fs::metadata(&loot) {
            assert!(
                !(loot_meta.ino() == victim_meta.ino() && loot_meta.dev() == victim_meta.dev()),
                "hardlink resolved against the process CWD: extracted entry shares an inode \
                 with {} outside dest_dir",
                victim.display(),
            );
        }
        Ok(())
    }

    /// Regression: the escaping-symlink defense must not depend on
    /// `strip_prefix` being set.
    ///
    /// Found by the `archive_extract` fuzz target. `extract_skips_escaping_symlink`
    /// covers `strip_prefix: Some(..)`, which runs the per-entry loop with its
    /// `link_name` check. `None` took the `else` branch — a bare
    /// `tar::Archive::unpack`, which writes link targets verbatim — so the
    /// identical tarball produced an escaping symlink on disk. Same bytes,
    /// same threat, opposite outcome.
    #[test]
    fn extract_without_strip_prefix_skips_escaping_symlink() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        extract_compressed_tar(
            &escaping_symlink_tar(false)[..],
            Compression::None,
            extract_dir.path(),
            None,
        )?;

        // symlink_metadata sees even a dangling link, so this is a real
        // "was never created" check.
        assert!(
            extract_dir
                .path()
                .join("prefix/link")
                .symlink_metadata()
                .is_err(),
            "escaping symlink was created without a strip_prefix",
        );
        Ok(())
    }

    /// The tar-slip write-through vector, exercised on the `strip_prefix: None`
    /// path. Nothing may land outside the destination tree.
    #[test]
    fn extract_without_strip_prefix_contains_write_through() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // Extraction may legitimately fail here; what must never happen is a
        // write escaping the tree.
        let _ = extract_compressed_tar(
            &escaping_symlink_tar(true)[..],
            Compression::None,
            extract_dir.path(),
            None,
        );

        // The defence is that the escaping link is never created: with no link
        // present, the follow-up entry writes into a real directory inside the
        // tree. Assert that directly — it is deterministic, unlike probing for
        // the escaped file, which may resolve to a system path we could not
        // have written to anyway (so its absence would prove nothing).
        let link = extract_dir.path().join("prefix/link");
        assert!(
            link.symlink_metadata()
                .map(|m| !m.file_type().is_symlink())
                .unwrap_or(true),
            "escaping symlink was created; a later entry could write through it",
        );

        // Belt and braces: nothing landed where the link *would* have resolved
        // to. The link lives at `prefix/link`, so its target is relative to
        // `prefix/` — the previous version of this check was one level too
        // high. A read error is the expected, good case and is spelled out
        // rather than coerced to "" by `unwrap_or_default`.
        let escaped = extract_dir
            .path()
            .join("prefix")
            .join("../../../etc/passwd");
        if let Ok(contents) = std::fs::read_to_string(&escaped) {
            assert_ne!(contents, "pwned", "write escaped the destination tree");
        }
        Ok(())
    }

    /// The xz arm's disk bound. Driving the real
    /// [`MAX_XZ_DECOMPRESSED_BYTES`] through `xz_decompress` would mean
    /// generating gigabytes, so the cap is tested where it actually lives —
    /// the writer — and wired into the xz arm by construction.
    #[test]
    fn limited_writer_stops_at_cap() {
        use std::io::Write as _;

        let mut w = LimitedWriter::new(Vec::new(), 8);
        assert_eq!(w.write(b"1234").unwrap(), 4);
        assert_eq!(w.write(b"5678").unwrap(), 4);
        assert!(!w.overflowed, "exactly at the cap is not an overflow");

        let err = w.write(b"9").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(w.overflowed);
        // Nothing past the cap reached the inner writer.
        assert_eq!(w.into_inner(), b"12345678");
    }

    /// A single write larger than the whole cap is rejected outright rather
    /// than partially accepted — decompressors hand over big buffers, and a
    /// short write would let the stream continue past the bound.
    #[test]
    fn limited_writer_rejects_oversized_single_write() {
        use std::io::Write as _;

        let mut w = LimitedWriter::new(Vec::new(), 4);
        assert!(w.write(b"toolong").is_err());
        assert!(w.overflowed);
        assert!(w.into_inner().is_empty());
    }

    #[test]
    fn extract_allows_in_tree_symlink() -> Result<(), ArchiveError> {
        let extract_dir = tempfile::tempdir().unwrap();

        // A relative symlink that stays within the extracted tree is fine.
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("prefix/sub/link").unwrap();
            header.set_link_name("../target").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, &[][..]).unwrap();
            builder.finish().unwrap();
        }

        extract_compressed_tar(
            &tar_data[..],
            Compression::None,
            extract_dir.path(),
            Some(&"prefix".to_string()),
        )?;

        assert!(extract_dir.path().join("sub/link").is_symlink());
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
        let (mut compressed_file, hash) = super::compress_dir(temp_dir.path(), None, &None)?;

        // Verify we got a hash
        assert_eq!(hash.len(), 32);

        // Verify we can read the compressed data
        let mut buffer = Vec::new();
        compressed_file.read_to_end(&mut buffer)?;
        assert!(!buffer.is_empty());

        Ok(())
    }
}
