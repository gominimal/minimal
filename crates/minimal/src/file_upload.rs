//! Streaming tar+zstd upload of the project directory to the daemon.
//!
//! The tar builder writes directly into a zstd encoder which writes
//! to the SSH channel stream — nothing is buffered in memory beyond
//! the encoder's internal buffer.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use async_tar::Builder;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Directories always skipped during upload. A proper .gitignore
/// implementation is tracked as a follow-up on #263.
const DEFAULT_EXCLUDED_DIRS: &[&str] = &["target", "node_modules"];

/// Marker entries whose presence at a directory root indicates it is a
/// version-control repository root. Used to decide whether the recursive
/// upload is obviously intentional or needs a confirmation prompt (#770).
///
/// Git worktrees/submodules use a `.git` *file* rather than a directory, so
/// the check must accept either — `Path::exists` does.
const VCS_MARKERS: &[&str] = &[".git", ".hg", ".svn", "CVS", ".jj"];

/// Maximum time the upload may make no forward progress before it is
/// abandoned with an error.
///
/// The upload writer is a russh `ChannelTx`, which parks on SSH window
/// availability. When the guest-side vsock connection is reset mid-transfer,
/// the peer never sends the window adjustment that would wake the writer, so
/// the write blocks with no waker and the client hangs indefinitely (#886) —
/// the same missed-wakeup failure class seen on the attach path (#588).
/// Bounding each write (and the final flush/shutdown) by an idle deadline
/// turns that silent hang into a surfaced error. Generous — a healthy channel
/// drains 256 KiB chunks in milliseconds, so this only trips the pathological
/// dead-peer case, never a slow-but-live transfer.
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns `true` if `dir` is the root of a recognized VCS repository
/// (Git, Mercurial, Subversion, CVS, or Jujutsu).
pub fn is_vcs_root(dir: &Path) -> bool {
    VCS_MARKERS.iter().any(|marker| dir.join(marker).exists())
}

fn is_default_excluded(name: &str) -> bool {
    DEFAULT_EXCLUDED_DIRS.contains(&name)
}

/// Streams a zstd-compressed tar archive of `dir` into `writer`.
///
/// The tar builder writes directly into the zstd encoder which writes
/// to `writer`, so the archive is never fully buffered in memory.
pub async fn stream_tar_zstd<W: AsyncWrite + Unpin + Send>(
    dir: &Path,
    mut writer: W,
) -> Result<(), anyhow::Error> {
    // async_tar::Builder requires W: Sync, but the SSH channel stream
    // is not Sync. Use a duplex pipe: the tar builder writes to one end
    // (in a background task), and we copy from the other end to writer.
    const PIPE_BUF: usize = 256 * 1024;
    let (tx, mut rx) = tokio::io::duplex(PIPE_BUF);

    let build = {
        let dir = dir.to_path_buf();
        tokio::spawn(async move { build_tar_zstd(&dir, tx).await })
    };

    copy_with_idle_timeout(&mut rx, &mut writer).await?;

    build.await.context("tar build task panicked")??;
    Ok(())
}

/// Copies the tar stream from `rx` into `writer`, then flushes and shuts the
/// writer down, bounding every write by [`UPLOAD_IDLE_TIMEOUT`].
///
/// Each `write_all` restarts the idle deadline, so a healthy transfer of any
/// size proceeds unbounded while a writer that stops accepting bytes — a dead
/// vsock peer whose window is never adjusted — surfaces as an error instead of
/// parking forever (#886). Returning on error drops `rx`, which fails the tar
/// builder's writes into the duplex and lets its task finish, so the caller's
/// `build.await` cannot deadlock against a still-running builder.
async fn copy_with_idle_timeout<R, W>(rx: &mut R, writer: &mut W) -> Result<(), anyhow::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = rx.read(&mut buf).await.context("reading tar stream")?;
        if n == 0 {
            break;
        }
        with_idle_deadline(writer.write_all(&buf[..n]), "copying tar stream to channel").await?;
    }
    with_idle_deadline(writer.flush(), "flushing upload stream").await?;
    with_idle_deadline(writer.shutdown(), "shutting down upload stream").await?;
    Ok(())
}

/// Awaits `op`, bounding it by [`UPLOAD_IDLE_TIMEOUT`]. A timeout is reported
/// as an error tagged with `what` so a stalled upload is diagnosable rather
/// than silent.
async fn with_idle_deadline<T>(
    op: impl std::future::Future<Output = std::io::Result<T>>,
    what: &'static str,
) -> Result<T, anyhow::Error> {
    match tokio::time::timeout(UPLOAD_IDLE_TIMEOUT, op).await {
        Ok(result) => result.context(what),
        Err(_) => Err(anyhow::anyhow!(
            "{what}: upload made no progress for {UPLOAD_IDLE_TIMEOUT:?}; \
             the transfer peer is likely gone"
        )),
    }
}

/// Builds a zstd-compressed tar archive of `dir` into `writer`, finalizing
/// the archive when done.
///
/// `async_tar::Builder` panics from its `Drop` impl if it is dropped without
/// `finish()` or `into_inner()` having been called. When the upload channel
/// closes mid-stream the entry writes fail, so the builder is always
/// finalized here — even on the error path — and the underlying failure is
/// surfaced as an error instead of crashing the worker thread.
async fn build_tar_zstd<W: AsyncWrite + Unpin + Send + Sync>(
    dir: &Path,
    writer: W,
) -> Result<(), anyhow::Error> {
    let encoder = async_compression::tokio::write::ZstdEncoder::new(writer);
    let mut tar = Builder::new(encoder);
    let entries = add_dir_entries(&mut tar, dir, "").await;
    // Finalize the builder regardless of whether adding entries succeeded, so
    // its Drop impl never fires the "dropped without finalizing" panic.
    let finalized = tar.into_inner().await;
    entries?;
    let mut encoder = finalized.context("finalizing tar archive")?;
    encoder.shutdown().await.context("flushing zstd encoder")?;
    Ok(())
}

async fn add_dir_entries<W: AsyncWrite + Unpin + Send + Sync>(
    tar: &mut Builder<W>,
    root: &Path,
    prefix: &str,
) -> Result<(), anyhow::Error> {
    add_dir_entries_inner(tar, root, prefix).await
}

fn add_dir_entries_inner<'a, W: AsyncWrite + Unpin + Send + Sync + 'a>(
    tar: &'a mut Builder<W>,
    root: &'a Path,
    prefix: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = match fs::read_dir(root).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::warn!("skipping unreadable directory: {}", root.display());
                return Ok(());
            }
            Err(e) => {
                return Err(
                    anyhow::Error::from(e).context(format!("reading directory {}", root.display()))
                );
            }
        };

        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    tracing::warn!("skipping unreadable entry in {}", root.display());
                    continue;
                }
                Err(e) => return Err(anyhow::Error::from(e).context("reading directory entry")),
            };

            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let entry_path = entry.path();

            // Skip common heavy/irrelevant directories.
            if is_default_excluded(&name_str) {
                let ft = match entry.file_type().await {
                    Ok(t) => t,
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
                    Err(e) => {
                        return Err(anyhow::Error::from(e)
                            .context(format!("getting file type for {}", entry_path.display())));
                    }
                };
                if ft.is_dir() {
                    continue;
                }
            }

            let archive_path = if prefix.is_empty() {
                name_str.to_string()
            } else {
                format!("{prefix}/{name_str}")
            };

            let file_type = match entry.file_type().await {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    tracing::warn!("skipping unreadable entry: {}", entry_path.display());
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::Error::from(e)
                        .context(format!("getting file type for {}", entry_path.display())));
                }
            };

            if file_type.is_dir() {
                let mut header = async_tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o755);
                header.set_entry_type(async_tar::EntryType::Directory);
                header.set_cksum();
                tar.append_data(&mut header, &archive_path, &[][..])
                    .await
                    .with_context(|| format!("adding directory {archive_path}"))?;

                add_dir_entries_inner(tar, &entry_path, &archive_path).await?;
            } else if file_type.is_symlink() {
                let target = fs::read_link(&entry_path)
                    .await
                    .with_context(|| format!("reading symlink {}", entry_path.display()))?;
                let mut header = async_tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_entry_type(async_tar::EntryType::Symlink);
                if let Some(t) = target.to_str() {
                    header.set_link_name(t).ok();
                }
                header.set_cksum();
                tar.append_data(&mut header, &archive_path, &[][..])
                    .await
                    .with_context(|| format!("adding symlink {archive_path}"))?;
            } else if file_type.is_file() {
                let mut file = match fs::File::open(&entry_path).await {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        tracing::warn!("skipping unreadable file: {}", entry_path.display());
                        continue;
                    }
                    Err(e) => {
                        return Err(anyhow::Error::from(e)
                            .context(format!("opening {}", entry_path.display())));
                    }
                };
                let metadata = file
                    .metadata()
                    .await
                    .with_context(|| format!("statting {}", entry_path.display()))?;
                let mut header = async_tar::Header::new_gnu();
                header.set_size(metadata.len());
                header.set_mode(0o644);
                header.set_entry_type(async_tar::EntryType::Regular);
                header.set_cksum();
                tar.append_data(&mut header, &archive_path, &mut file)
                    .await
                    .with_context(|| format!("adding file {archive_path}"))?;
            }
            // Skip sockets, FIFOs, block/char devices, etc.
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A writer that accepts `remaining` bytes and then fails every write,
    /// simulating the upload channel closing while the tar stream is still
    /// being written.
    struct FailingWriter {
        remaining: usize,
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "channel closed",
                )));
            }
            let n = buf.len().min(self.remaining);
            self.remaining -= n;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A writer that accepts `remaining` bytes and then parks forever,
    /// returning `Poll::Pending` without registering a waker — simulating a
    /// russh `ChannelTx` whose vsock peer died without a window adjustment, so
    /// the write can never make progress and is never woken.
    struct StallingWriter {
        remaining: usize,
    }

    impl AsyncWrite for StallingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(self.remaining);
            self.remaining -= n;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    /// Fills `len` bytes with an incompressible LCG sequence so the zstd
    /// encoder is forced to flush to the underlying writer mid-stream.
    fn incompressible(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (s >> 33) as u8
            })
            .collect()
    }

    /// Regression test for the async-tar "Builder dropped without finalizing"
    /// panic: when the writer fails mid-stream, building must surface an error
    /// rather than dropping the un-finalized builder and panicking.
    #[tokio::test]
    async fn build_surfaces_error_when_writer_fails_mid_stream() {
        let dir = tempfile::TempDir::new().unwrap();
        for i in 0..64 {
            std::fs::write(
                dir.path().join(format!("f{i}.bin")),
                incompressible(i as u64 + 1, 32 * 1024),
            )
            .unwrap();
        }

        let writer = FailingWriter { remaining: 1024 };
        let result = build_tar_zstd(dir.path(), writer).await;
        assert!(
            result.is_err(),
            "a mid-stream writer failure must surface as an error, not a panic"
        );
    }

    /// Regression test for #886: when the upload writer accepts some bytes and
    /// then parks forever with no waker (a dead vsock peer whose window is
    /// never adjusted), the upload must surface an error via the idle deadline
    /// instead of hanging indefinitely. Runs on a paused clock so the runtime
    /// auto-advances to the timeout the moment no task can make progress.
    #[tokio::test(start_paused = true)]
    async fn stream_times_out_when_writer_stalls_mid_stream() {
        let dir = tempfile::TempDir::new().unwrap();
        for i in 0..64 {
            std::fs::write(
                dir.path().join(format!("f{i}.bin")),
                incompressible(i as u64 + 1, 32 * 1024),
            )
            .unwrap();
        }

        let writer = StallingWriter { remaining: 1024 };
        let result = stream_tar_zstd(dir.path(), writer).await;
        assert!(
            result.is_err(),
            "a stalled upload must surface as an error, not hang indefinitely"
        );
    }

    /// Streams a tar+zstd archive into a buffer, decompresses it, unpacks
    /// it into a tempdir, and returns the list of all file/symlink paths
    /// (relative) found by walking the unpacked tree.
    async fn stream_and_list(dir: &Path) -> Vec<String> {
        let mut buf = Vec::new();
        stream_tar_zstd(dir, &mut buf).await.unwrap();

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&buf[..]);
        let out = tempfile::TempDir::new().unwrap();
        let archive = async_tar::Archive::new(decoder);
        archive.unpack(out.path().to_path_buf()).await.unwrap();

        let mut paths = Vec::new();
        fn walk(dir: &std::path::Path, base: &std::path::Path, paths: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                let ftype = entry.file_type().unwrap();
                if ftype.is_file() || ftype.is_symlink() {
                    paths.push(rel);
                } else if ftype.is_dir() {
                    walk(&path, base, paths);
                }
            }
        }
        walk(out.path(), out.path(), &mut paths);
        paths
    }

    #[tokio::test]
    async fn stream_skips_unix_sockets() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello").unwrap();
        let _socket = UnixListener::bind(dir.path().join("sock")).unwrap();

        let paths = stream_and_list(dir.path()).await;
        assert!(
            paths.iter().any(|p| p == "hello.txt"),
            "hello.txt should be in the archive"
        );
        assert!(!paths.iter().any(|p| p == "sock"), "sock should be skipped");
    }

    #[tokio::test]
    async fn stream_skips_permission_denied_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("readable.txt"), "ok").unwrap();

        let restricted = dir.path().join("restricted");
        std::fs::create_dir(&restricted).unwrap();
        std::fs::write(restricted.join("secret.txt"), "secret").unwrap();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();

        let paths = stream_and_list(dir.path()).await;
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o755)).ok();

        assert!(
            paths.iter().any(|p| p == "readable.txt"),
            "readable.txt should be in the archive"
        );
        assert!(
            !paths.iter().any(|p| p.contains("secret")),
            "restricted/secret.txt should be skipped"
        );
    }

    #[tokio::test]
    async fn stream_includes_regular_files_dirs_and_symlinks() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "content").unwrap();
        std::fs::create_dir_all(dir.path().join("subdir")).unwrap();
        std::fs::write(dir.path().join("subdir/nested.txt"), "nested").unwrap();
        std::os::unix::fs::symlink("file.txt", dir.path().join("link")).unwrap();

        let paths = stream_and_list(dir.path()).await;
        assert!(paths.iter().any(|p| p == "file.txt"), "file.txt missing");
        assert!(
            paths.iter().any(|p| p == "subdir/nested.txt"),
            "nested.txt missing"
        );
        assert!(paths.iter().any(|p| p == "link"), "symlink missing");
    }

    #[tokio::test]
    async fn stream_does_not_follow_symlinks_to_external_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let external = tempfile::TempDir::new().unwrap();
        std::fs::write(external.path().join("secret"), "sensitive").unwrap();

        std::os::unix::fs::symlink(external.path().join("secret"), dir.path().join("escape"))
            .unwrap();
        std::fs::write(dir.path().join("safe.txt"), "safe").unwrap();

        let mut buf = Vec::new();
        stream_tar_zstd(dir.path(), &mut buf).await.unwrap();

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&buf[..]);
        let out = tempfile::TempDir::new().unwrap();
        let archive = async_tar::Archive::new(decoder);
        archive.unpack(out.path().to_path_buf()).await.unwrap();

        let escape_path = out.path().join("escape");
        assert!(
            escape_path.is_symlink(),
            "escape should be a symlink, not a copied file"
        );
        assert!(out.path().join("safe.txt").is_file());
    }

    #[tokio::test]
    async fn stream_excludes_default_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "keep").unwrap();
        std::fs::create_dir_all(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("target/binary.o"), "binary").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules/lib.js"), "lib").unwrap();

        let paths = stream_and_list(dir.path()).await;
        assert!(
            paths.iter().any(|p| p == "keep.txt"),
            "keep.txt should be uploaded"
        );
        assert!(
            !paths.iter().any(|p| p.contains("target/")),
            "target/ should be excluded"
        );
        assert!(
            !paths.iter().any(|p| p.contains("node_modules/")),
            "node_modules/ should be excluded"
        );
    }

    #[test]
    fn is_vcs_root_recognizes_git() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_recognizes_git_file() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(".git"), "gitdir: /some/elsewhere\n").unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_recognizes_mercurial() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".hg")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_recognizes_subversion() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".svn")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_recognizes_cvs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("CVS")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_recognizes_jujutsu() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".jj")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_false_for_plain_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello").unwrap();
        assert!(!is_vcs_root(dir.path()));
    }
}
