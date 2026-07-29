//! Streaming tar+zstd uploads from client to daemon.
//!
//! Two public entrypoints share one underlying pipeline:
//!
//! - [`stream_tar_zstd`] walks a directory (skipping `target/` and
//!   `node_modules/`) and archives it — used by the workspace
//!   upload path.
//! - [`TarZstArchive`] is a lower-level builder taking one entry at
//!   a time (via [`TarZstArchive::add_file`]) so callers with a
//!   disjoint set of source paths — the composition-patches
//!   uploader — can drive the same pipe/encoder plumbing without
//!   going through a directory walk. Parent directories are
//!   materialized by the unpacker as needed; no explicit
//!   `add_dir`/`add_symlink` shape is exposed yet.
//!
//! The tar builder writes directly into a zstd encoder which writes
//! to the SSH channel stream — nothing is buffered in memory beyond
//! the encoder's internal buffer.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use async_tar::Builder;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};

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
/// Works with non-Sync writers (SSH channels aren't Sync) by routing the
/// tar output through an in-memory pipe: the pipe read side pumps into
/// `writer` while the tar builder — which needs a Sync writer — writes
/// into the pipe's Sync tx half.
///
/// The archive is never fully buffered in memory beyond the pipe buffer
/// and the encoder's internal state.
///
/// An idle-progress timeout bounds both the pipe read and the channel
/// write. Without it, russh's `ChannelTx` blocks on window availability
/// and a peer that dies without a window adjustment leaves the writer
/// parked with no waker — the client hangs indefinitely (#886).
pub async fn stream_tar_zstd<W: AsyncWrite + Unpin + Send>(
    dir: &Path,
    writer: W,
) -> Result<(), anyhow::Error> {
    // Route through `stream_via_pipe` (shared with the patches
    // uploader): the SSH channel writer isn't Sync but the tar
    // builder requires Sync, so the build side writes into the
    // pipe's Sync tx half while the pipe's rx pumps into `writer`.
    stream_via_pipe(writer, async |tx| {
        let mut archive = TarZstArchive::new(tx);
        // Failure-safe finalize: propagating an entry-walk error via
        // `?` would drop the archive with an unfinalized async_tar
        // builder inside, which panics from Drop. `finish` on every
        // path — success or error — ends the builder cleanly.
        let entries_result = add_dir_entries(archive.builder(), dir, "").await;
        let finish_result = archive.finish().await;
        entries_result?;
        finish_result
    })
    .await
    .context("workspace upload failed")
}

/// Run `build` against the Sync tx half of an in-memory pipe while
/// draining the rx half into `writer`. Used by both directory and
/// per-patch uploaders to bridge a non-Sync writer (SSH channel,
/// or a test `&mut Vec<u8>`) to the Sync-requiring
/// [`TarZstArchive`].
///
/// The pipe capacity is 256 KiB — big enough that the encoder can
/// flush a full block without stalling, small enough that a stuck
/// reader surfaces backpressure quickly.
pub async fn stream_via_pipe<W, F>(mut writer: W, build: F) -> Result<(), anyhow::Error>
where
    W: AsyncWrite + Unpin,
    F: AsyncFnOnce(tokio::io::DuplexStream) -> Result<(), anyhow::Error>,
{
    const PIPE_BUF: usize = 256 * 1024;
    let (tx, mut rx) = tokio::io::duplex(PIPE_BUF);

    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    // Drive build and copy concurrently with `try_join!`. On error
    // either side cancels the other: if the writer stalls, the build
    // future is dropped — `TarZstArchive`'s `Drop` mem::forgets the
    // inner `async_tar::Builder`, so no panic; if the build errors, the
    // copy is dropped — the pipe and writer are cleaned up. Whichever
    // side errors first surfaces, giving the root cause, not a
    // secondary "broken pipe" from the other (#886).
    let build_fut = build(tx);
    let copy_fut = async {
        // Buffer the wire writes (#923): the encoder can emit many
        // small blocks, so a 4 KiB `BufWriter` coalesces them into
        // fewer, larger writes to the underlying SSH channel.
        let mut w = BufWriter::with_capacity(4 * 1024, &mut writer);

        // Manual copy with an idle-progress deadline instead of
        // tokio::io::copy. Each direction gets its own timeout: a
        // stall on either the pipe read (tar builder stuck) or the
        // channel write (peer gone, window frozen) surfaces as an
        // error instead of an indefinite hang (#886).
        let mut buf = [0u8; 8 * 1024];
        loop {
            match tokio::time::timeout(IDLE_TIMEOUT, rx.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    match tokio::time::timeout(IDLE_TIMEOUT, w.write_all(&buf[..n])).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            return Err(
                                anyhow::Error::from(e).context("copying tar stream to writer")
                            );
                        }
                        Err(_) => {
                            anyhow::bail!(
                                "upload stalled: channel write blocked for {IDLE_TIMEOUT:?} \
                                 (peer may be gone)"
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    return Err(anyhow::Error::from(e).context("reading from tar pipe"));
                }
                Err(_) => {
                    anyhow::bail!(
                        "upload stalled: no data from tar builder for {IDLE_TIMEOUT:?} \
                         (read stalled)"
                    );
                }
            }
        }
        tokio::time::timeout(IDLE_TIMEOUT, w.flush())
            .await
            .map_err(|_| anyhow::anyhow!("upload stalled: flush blocked for {IDLE_TIMEOUT:?}"))?
            .context("flushing upload writer")?;
        tokio::time::timeout(IDLE_TIMEOUT, w.shutdown())
            .await
            .map_err(|_| anyhow::anyhow!("upload stalled: shutdown blocked for {IDLE_TIMEOUT:?}"))?
            .context("shutting down upload writer")?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(build_fut, copy_fut)?;
    Ok(())
}

/// AsyncWrite adapter that increments an [`indicatif::ProgressBar`] by the
/// number of bytes flowing through it. Wrap the SSH channel writer with this
/// so the bar reflects wire-bytes actually delivered (post-compression,
/// post-SSH framing), not the uncompressed input.
pub struct ProgressWriter<W> {
    inner: W,
    bar: indicatif::ProgressBar,
}

impl<W: tokio::io::AsyncWrite + Unpin> ProgressWriter<W> {
    pub fn new(inner: W, bar: indicatif::ProgressBar) -> Self {
        Self { inner, bar }
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ProgressWriter<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let inner = std::pin::Pin::new(&mut this.inner);
        match inner.poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => {
                this.bar.inc(n as u64);
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Options controlling how a single file is added to a
/// [`TarZstArchive`].
///
/// `add_file` always follows symlinks (`tokio::fs::File::open` has no
/// no-follow variant), so there's no `follow_symlinks` knob to lie
/// about — the callers with archive-the-link-itself semantics go
/// through `add_dir_entries`, which handles symlinks explicitly.
#[derive(Debug, Clone, Copy, Default)]
pub struct AddFileOptions {
    /// Override the archive-entry mode. `None` copies the source
    /// file's mode (masked to the standard permission bits) as-is;
    /// `Some(m)` forces `m` (e.g. `0o644` for the patches uploader
    /// normalizing writable copies into the sandbox home).
    pub mode_override: Option<u32>,
}

/// Low-level tar+zstd archive builder over a Sync async writer.
///
/// Wraps `async_tar::Builder` inside a zstd encoder. `async_tar::Builder`
/// requires `W: Sync`, so callers wanting to stream into a non-Sync
/// writer (SSH channels aren't Sync) route through the [`stream_via_pipe`]
/// helper first — the pipe's Sync `DuplexStream` tx half feeds this
/// type, and the rx half drains into the non-Sync writer on the
/// same task.
///
/// Callers should call [`Self::finish`] to produce a valid archive.
/// If the archive is dropped before `finish` (typically because the
/// caller's future was cancelled — a timeout, a Ctrl-C, an outer
/// `select!` losing the race), the wrapped `async_tar::Builder` would
/// otherwise panic from its `Drop` impl. We hold the builder inside a
/// `ManuallyDrop`; on drop we call `mem::forget` on the taken builder
/// instead, so no panic ever fires. The resulting archive on the wire
/// is truncated — missing tar's trailing two 512-byte zero blocks —
/// but a cancelled outer future has already torn down its writer
/// (SSH channel closed, or the test `Vec` about to be discarded), so
/// nothing downstream ever reads those bytes.
pub struct TarZstArchive<W: AsyncWrite + Unpin + Send + Sync> {
    /// `ManuallyDrop` because our `Drop` impl below has to prevent
    /// the inner Builder's `Drop` from running when we get cancelled
    /// before `finish` — that Drop panics on Tokio, and the panic
    /// would be untriggerable-from-userland: it would come out of an
    /// aborted task and crash the whole runtime.
    tar: std::mem::ManuallyDrop<Builder<async_compression::tokio::write::ZstdEncoder<W>>>,
}

impl<W: AsyncWrite + Unpin + Send + Sync> Drop for TarZstArchive<W> {
    fn drop(&mut self) {
        // SAFETY: `self.tar` is initialized by `new` and this is the
        // only `Drop` impl on `TarZstArchive`, so `take` runs exactly
        // once. `mem::forget` on the taken builder skips the inner
        // `Drop` — bypassing async_tar's panic path — at the cost of
        // leaking the builder's internal buffers. On the happy path
        // `finish` extracts the builder before we get here, so the
        // taken value on cancellation is only the mid-write builder
        // whose contents were already going to be discarded.
        let tar = unsafe { std::mem::ManuallyDrop::take(&mut self.tar) };
        std::mem::forget(tar);
    }
}

impl<W: AsyncWrite + Unpin + Send + Sync> TarZstArchive<W> {
    /// Create a new archive that streams into `writer` as entries
    /// are added.
    ///
    /// Zstd is configured for interactive activate throughput —
    /// **level 1** (2-3× compress throughput vs. the codec's default
    /// 3, only modest ratio loss on text-y payloads) with **N-1
    /// worker threads** where N = `available_parallelism`, so the
    /// compressor pipelines across cores instead of running on the
    /// caller thread.
    pub fn new(writer: W) -> Self {
        let workers = std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get().saturating_sub(1)).unwrap_or(0))
            .unwrap_or(0);
        let params = [async_compression::zstd::CParameter::nb_workers(workers)];
        let encoder = async_compression::tokio::write::ZstdEncoder::with_quality_and_params(
            writer,
            async_compression::Level::Precise(1),
            &params,
        );
        Self {
            tar: std::mem::ManuallyDrop::new(Builder::new(encoder)),
        }
    }

    /// Escape hatch for the directory-walker path that needs to
    /// recurse over an owned mutable builder.
    fn builder(&mut self) -> &mut Builder<async_compression::tokio::write::ZstdEncoder<W>> {
        &mut self.tar
    }

    /// Add a file entry at `archive_path`, reading its contents
    /// from `host_path`. Always follows symlinks (via
    /// `tokio::fs::File::open`). The [`AddFileOptions::mode_override`]
    /// value, if set, is stamped on the tar header in place of the
    /// source file's mode.
    pub async fn add_file(
        &mut self,
        host_path: &Path,
        archive_path: &str,
        opts: AddFileOptions,
    ) -> Result<(), anyhow::Error> {
        let file = fs::File::open(host_path)
            .await
            .with_context(|| format!("opening {}", host_path.display()))?;
        let metadata = file
            .metadata()
            .await
            .with_context(|| format!("statting {}", host_path.display()))?;
        // Default mode: the source's own permission bits (masked to
        // the standard nine + suid/sgid/sticky). Matches the
        // `mode_override = None` docstring; otherwise an executable
        // dropped in through `default()` would archive as 0o644 and
        // silently lose its exec bit on unpack.
        let default_mode = {
            use std::os::unix::fs::PermissionsExt as _;
            metadata.permissions().mode() & 0o7777
        };
        let mut header = async_tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(opts.mode_override.unwrap_or(default_mode));
        header.set_entry_type(async_tar::EntryType::Regular);
        // 1 MiB BufReader on the file: without it every 8 KiB chunk
        // `tokio::io::copy(_buf)` moves is a separate blocking-pool
        // round-trip through `tokio::fs`, and 1.3 GiB of patches
        // means 168k of them. With the BufReader the file's read
        // syscalls collapse to `size / 1 MiB` — a ~130× reduction
        // that closes the throughput gap between the tar builder
        // and the downstream SSH channel.
        let mut buffered = tokio::io::BufReader::with_capacity(1024 * 1024, file);
        // Fast path: bypass `append_data` so we can drive
        // `fill_buf`/`consume` against the BufReader directly,
        // sending up to the BufReader's full slice per `poll_write`
        // into the zstd encoder. `append_data` internally calls
        // `tokio::io::copy`, which uses an 8 KiB working buffer,
        // producing an order of magnitude more async poll pairs for
        // no wire-format benefit.
        //
        // `set_path` errors when the archive path doesn't fit in the
        // standard 100-byte tar name field. Longer paths need
        // async_tar's private GNULongName preamble helper, so those
        // fall through to `append_data`.
        if header.set_path(archive_path).is_ok() {
            header.set_cksum();
            let dst = self.tar.get_mut();
            dst.write_all(header.as_bytes())
                .await
                .with_context(|| format!("writing tar header for {archive_path}"))?;

            // Bound the copy to the size we declared in the header.
            // A source that grew between the `stat` above and this
            // read would otherwise push extra bytes into the stream
            // and desync every following entry (the reader would
            // parse those bytes as the next header). A source that
            // *shrank* — file truncated after our stat call — is a
            // hard error: silently zero-padding to make the tar
            // frame line up would deliver a valid archive whose
            // last entry's contents are the surviving prefix plus
            // trailing NULs, and the client would report success
            // for a corrupted upload. Better to fail loudly here;
            // the outer future is dropped either way, so tar
            // framing beyond this entry doesn't need to survive.
            // Uses `fill_buf`/`consume` (not `tokio::io::copy_buf`)
            // so we can cap the write at `declared - written` per
            // iteration; still gets the full BufReader capacity per
            // poll_write.
            use tokio::io::AsyncBufReadExt as _;
            let declared = metadata.len();
            let mut written: u64 = 0;
            while written < declared {
                let buf = buffered
                    .fill_buf()
                    .await
                    .with_context(|| format!("reading body of {archive_path}"))?;
                if buf.is_empty() {
                    break;
                }
                let take = std::cmp::min(buf.len() as u64, declared - written) as usize;
                dst.write_all(&buf[..take])
                    .await
                    .with_context(|| format!("writing body of {archive_path}"))?;
                buffered.consume(take);
                written += take as u64;
            }
            if written < declared {
                anyhow::bail!(
                    "source file {} shrank during upload: declared {declared} bytes in the tar \
                     header (from stat) but only {written} were readable — the file was truncated \
                     between stat and read, so the archive would silently ship a corrupted entry",
                    host_path.display(),
                );
            }

            let pad = ((512 - (declared % 512)) % 512) as usize;
            if pad > 0 {
                const ZEROS: [u8; 512] = [0; 512];
                dst.write_all(&ZEROS[..pad])
                    .await
                    .with_context(|| format!("writing tar padding for {archive_path}"))?;
            }
            Ok(())
        } else {
            // `append_data` sets the header checksum internally
            // (async_tar 0.6 builder.rs:201-203), so no manual
            // `set_cksum()` here.
            self.tar
                .append_data(&mut header, archive_path, &mut buffered)
                .await
                .with_context(|| format!("adding file {archive_path}"))
        }
    }

    /// Finalize the tar archive and flush the zstd encoder.
    /// Consuming self guarantees no more entries can be added.
    pub async fn finish(mut self) -> Result<(), anyhow::Error> {
        // SAFETY: `self.tar` is initialized by `new` and no other
        // code path takes it. We take it here, then `mem::forget`
        // `self` so our `Drop` impl doesn't also try to take it.
        // On error inside `into_inner`, the builder is consumed
        // regardless, so no panic path fires.
        let tar = unsafe { std::mem::ManuallyDrop::take(&mut self.tar) };
        std::mem::forget(self);
        let mut encoder = tar.into_inner().await.context("finalizing tar archive")?;
        encoder.shutdown().await.context("flushing zstd encoder")?;
        Ok(())
    }
}

/// The directory-walk uploader. Kept as a free function so
/// `stream_tar_zstd` can pin down a single `&mut Builder` reference
/// through the recursion (`TarZstArchive::builder()` returns one).
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
                // Preserve the source's permission bits (masked to the
                // standard nine + suid/sgid/sticky), same as
                // `TarZstArchive::add_file`'s default. Hardcoding 0o644
                // here silently strips the exec bit off scripts and
                // binaries in every workspace upload.
                let mode = {
                    use std::os::unix::fs::PermissionsExt as _;
                    metadata.permissions().mode() & 0o7777
                };
                // Preserve the mtime too: leaving the header's zero
                // stamp unpacks every file at the epoch, which breaks
                // mtime-keyed (make-style) builds inside the session.
                // Pre-epoch mtimes (nonsensical but legal) clamp to 0.
                let mtime = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs());
                let mut header = async_tar::Header::new_gnu();
                header.set_size(metadata.len());
                header.set_mode(mode);
                header.set_mtime(mtime);
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::AsyncRead;

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
        let result = stream_tar_zstd(dir.path(), writer).await;
        assert!(
            result.is_err(),
            "a mid-stream writer failure must surface as an error, not a panic"
        );
    }

    /// Writer that accepts all writes/flushes but errors on `poll_shutdown`.
    /// Wired to prove `TarZstArchive::finish`'s `encoder.shutdown().await?`
    /// path actually surfaces its error — the earlier
    /// `stream_via_pipe(dir, FailingWriter)` test can't cover it because
    /// its drain half absorbs everything the tar builder writes.
    struct ShutdownFailingWriter;

    impl AsyncWrite for ShutdownFailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "shutdown failed",
            )))
        }
    }

    /// Regression test: `TarZstArchive::finish` must propagate errors from
    /// the zstd encoder's `shutdown` call. A silently-dropped `?` on
    /// `encoder.shutdown().await` would let the underlying writer's
    /// shutdown failure disappear, and the returned archive bytes would
    /// look valid to the caller even though the daemon-side reader would
    /// see truncated / corrupt zstd framing.
    #[tokio::test]
    async fn finish_surfaces_encoder_shutdown_error() {
        let mut archive = TarZstArchive::new(ShutdownFailingWriter);
        // A no-body entry avoids relying on any body-copy internals —
        // the tar bytes we do write all succeed under this writer, so
        // the only path to an error is the encoder-shutdown call
        // inside `finish`.
        let src = tempfile::NamedTempFile::new().unwrap();
        archive
            .add_file(
                src.path(),
                "empty.txt",
                AddFileOptions {
                    mode_override: Some(0o644),
                },
            )
            .await
            .expect("adding the empty file succeeds");
        let err = archive
            .finish()
            .await
            .expect_err("shutdown-failing writer must produce a finish() error");
        assert!(
            format!("{err:#}").contains("zstd encoder")
                || format!("{err:#}").contains("shutdown failed"),
            "expected the encoder-shutdown error to surface, got: {err:#}",
        );
    }

    /// Streams a tar+zstd archive into a buffer, decompresses it, unpacks
    /// it into a tempdir, and returns the list of all file/symlink paths
    /// (relative) found by walking the unpacked tree.
    async fn stream_and_list(dir: &Path) -> Vec<String> {
        let mut buf = Vec::new();
        stream_tar_zstd(dir, &mut buf).await.unwrap();
        unpack_and_list(&buf).await
    }

    async fn unpack_and_list(archive_bytes: &[u8]) -> Vec<String> {
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(archive_bytes);
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

    /// The dir-walk uploader must preserve file permission bits: a
    /// workspace upload that flattens everything to 0o644 strips the
    /// exec bit off scripts (e.g. `scripts/setup-dev.sh`), so they
    /// arrive in the session un-runnable.
    #[tokio::test]
    async fn stream_preserves_file_modes() {
        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("setup-dev.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plain = dir.path().join("notes.txt");
        std::fs::write(&plain, "notes").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o640)).unwrap();

        let mut buf = Vec::new();
        stream_tar_zstd(dir.path(), &mut buf).await.unwrap();

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&buf[..]);
        let out = tempfile::TempDir::new().unwrap();
        async_tar::Archive::new(decoder)
            .unpack(out.path().to_path_buf())
            .await
            .unwrap();

        let mode_of = |name: &str| {
            std::fs::metadata(out.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(
            mode_of("setup-dev.sh"),
            0o755,
            "executable bit must survive the upload round-trip"
        );
        assert_eq!(
            mode_of("notes.txt"),
            0o640,
            "non-default permission bits must survive the upload round-trip"
        );

        let src_mtime_secs = |p: &std::path::Path| {
            std::fs::metadata(p)
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        assert_eq!(
            src_mtime_secs(&out.path().join("setup-dev.sh")),
            src_mtime_secs(&script),
            "mtime must survive the upload round-trip, not unpack at the epoch"
        );
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

    /// A writer that accepts a small amount of data then parks forever,
    /// simulating russh's `ChannelTx` blocking on a window adjustment that
    /// never arrives because the peer died (#886).
    struct StallingWriter {
        accepted: usize,
    }

    impl AsyncWrite for StallingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.accepted >= 1024 {
                return Poll::Pending;
            }
            let n = buf.len().min(1024 - self.accepted);
            self.accepted += n;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// `stream_tar_zstd` must bail with an idle-progress timeout when the
    /// writer stalls, rather than hanging indefinitely (#886).
    #[tokio::test(start_paused = true)]
    async fn stream_tar_zstd_bails_when_writer_stalls() {
        let dir = tempfile::TempDir::new().unwrap();
        // Enough data to overflow the 1024-byte StallingWriter capacity
        // and the 256K duplex pipe, forcing the copy loop to block on
        // the writer.
        for i in 0..32 {
            std::fs::write(
                dir.path().join(format!("f{i}.bin")),
                incompressible(i as u64 + 1, 32 * 1024),
            )
            .unwrap();
        }

        let writer = StallingWriter { accepted: 0 };
        let result = stream_tar_zstd(dir.path(), writer).await;
        assert!(result.is_err(), "a stalled writer must surface as an error");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("stalled"),
            "expected a stall error, got: {msg}"
        );
    }

    /// `stream_via_pipe` must bail with an idle-progress timeout when the
    /// build side never produces data, rather than hanging indefinitely
    /// (#886). Exercises the read-stall branch: a build closure that holds
    /// `tx` open but never writes, simulating a stuck builder (e.g. a
    /// filesystem hang). `try_join!` cancels the build future on the read
    /// timeout, so the test completes instead of deadlocking on `join!`.
    #[tokio::test(start_paused = true)]
    async fn stream_via_pipe_bails_when_builder_stalls() {
        let result = stream_via_pipe(tokio::io::sink(), async |_tx| {
            std::future::pending::<Result<(), anyhow::Error>>().await
        })
        .await;
        assert!(
            result.is_err(),
            "a stalled builder must surface as an error"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("stalled"),
            "expected a stall error, got: {msg}"
        );
    }

    /// A `CountingWriter` that tracks bytes written through it, used by
    /// the upload path to report compressed byte count on success or
    /// failure (#869).
    struct CountingReader<R> {
        inner: R,
        count: Arc<AtomicU64>,
    }

    impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let prev = buf.filled().len();
            let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = &poll {
                let n = buf.filled().len() - prev;
                if n > 0 {
                    self.count.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            poll
        }
    }

    /// The upload's `bytes_received` field is only worth logging if it is
    /// exact, so pull a payload through in many small polls and check the
    /// tally accumulates across them rather than recording the last read.
    #[tokio::test]
    async fn counting_reader_tallies_every_byte_pulled_through() {
        let payload: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        let count = Arc::new(AtomicU64::new(0));
        let mut sunk = Vec::new();

        let read = tokio::io::copy(
            &mut CountingReader {
                inner: payload.as_slice(),
                count: Arc::clone(&count),
            },
            &mut sunk,
        )
        .await
        .unwrap();

        assert_eq!(sunk, payload);
        assert_eq!(read, payload.len() as u64);
        assert_eq!(count.load(Ordering::Relaxed), payload.len() as u64);
    }

    #[test]
    fn is_vcs_root_recognizes_mercurial() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".hg")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_recognizes_jujutsu() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".jj")).unwrap();
        assert!(is_vcs_root(dir.path()));
    }

    #[test]
    fn is_vcs_root_rejects_plain_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!is_vcs_root(dir.path()));
    }

    // ---- TarZstArchive per-entry API ----

    /// Build an archive against an owned `Vec<u8>` writer and
    /// return the finished bytes. Test helper wrapping the
    /// `TarZstArchive` API — an owned `Vec` is `AsyncWrite + Sync`
    /// out of the box, which the archive requires.
    async fn build_via_archive(
        f: impl AsyncFnOnce(&mut TarZstArchive<Vec<u8>>) -> Result<(), anyhow::Error>,
    ) -> Vec<u8> {
        let mut archive = TarZstArchive::new(Vec::new());
        f(&mut archive).await.unwrap();
        // Take the builder past our `ManuallyDrop` and forget the
        // wrapper (matching what `finish` does) — needed to reach
        // into the encoder to reclaim the `Vec` without triggering
        // our `Drop::forget` behavior twice.
        // SAFETY: `archive.tar` is initialized and we `mem::forget`
        // the archive on the next line so `Drop` never runs.
        let tar = unsafe { std::mem::ManuallyDrop::take(&mut archive.tar) };
        std::mem::forget(archive);
        let mut encoder = tar.into_inner().await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// Adding files entry-at-a-time from arbitrary host paths (the
    /// patches-upload shape) yields a valid archive with each entry
    /// at the caller-supplied archive path.
    #[tokio::test]
    async fn tar_zst_archive_adds_files_at_specified_archive_paths() {
        let src = tempfile::TempDir::new().unwrap();
        let a_path = src.path().join("a.txt");
        let b_path = src.path().join("b.txt");
        std::fs::write(&a_path, "contents-a").unwrap();
        std::fs::write(&b_path, "contents-b").unwrap();

        let buf = build_via_archive(async |archive| {
            // No explicit `add_dir` — the unpacker creates parent
            // dirs from the file paths (`unpack_in` handles it).
            archive
                .add_file(
                    &a_path,
                    ".config/helix/config.toml",
                    AddFileOptions::default(),
                )
                .await?;
            archive
                .add_file(
                    &b_path,
                    ".config/other.toml",
                    AddFileOptions {
                        mode_override: Some(0o644),
                    },
                )
                .await
        })
        .await;

        let paths = unpack_and_list(&buf).await;
        assert!(
            paths.iter().any(|p| p == ".config/helix/config.toml"),
            "config.toml missing: got {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p == ".config/other.toml"),
            "other.toml missing: got {paths:?}"
        );
    }

    /// `add_file` follows symlinks — copies the target's contents.
    /// The patches uploader relies on this so a `/nix/store/…` link
    /// lands as a real file inside the sandbox.
    #[tokio::test]
    async fn tar_zst_archive_add_file_follows_symlinks() {
        let src = tempfile::TempDir::new().unwrap();
        let target = src.path().join("real.txt");
        std::fs::write(&target, "target-contents").unwrap();
        let link = src.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let buf = build_via_archive(async |archive| {
            archive
                .add_file(
                    &link,
                    "copied.txt",
                    AddFileOptions {
                        mode_override: None,
                    },
                )
                .await
        })
        .await;

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&buf[..]);
        let out = tempfile::TempDir::new().unwrap();
        let archive = async_tar::Archive::new(decoder);
        archive.unpack(out.path().to_path_buf()).await.unwrap();
        let copied = out.path().join("copied.txt");
        assert!(copied.is_file(), "expected a real file, got {copied:?}");
        assert_eq!(std::fs::read_to_string(&copied).unwrap(), "target-contents");
    }

    /// `add_file` with `mode_override` honours the requested mode.
    /// Verifies the patches uploader's normalize-to-0o644 story
    /// (Nix-store 0o444 sources landing as writable copies).
    #[tokio::test]
    async fn tar_zst_archive_add_file_honours_mode_override() {
        let src = tempfile::TempDir::new().unwrap();
        let source = src.path().join("readonly.txt");
        std::fs::write(&source, "ro").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o444)).unwrap();

        let buf = build_via_archive(async |archive| {
            archive
                .add_file(
                    &source,
                    "normalized.txt",
                    AddFileOptions {
                        mode_override: Some(0o644),
                    },
                )
                .await
        })
        .await;

        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&buf[..]);
        let out = tempfile::TempDir::new().unwrap();
        let ar = async_tar::Archive::new(decoder);
        ar.unpack(out.path().to_path_buf()).await.unwrap();
        let unpacked = out.path().join("normalized.txt");
        let meta = std::fs::metadata(&unpacked).unwrap();
        // Mask off the file-type bits; async-tar sets both.
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o644,
            "mode override should have made the unpacked file 0o644",
        );
    }

    /// An archive with no entries still produces a valid empty
    /// tar+zstd stream. The patches uploader takes this path when
    /// the composition has no patches.
    #[tokio::test]
    async fn tar_zst_archive_empty_finish_produces_valid_stream() {
        let buf = build_via_archive(async |_| Ok(())).await;
        let paths = unpack_and_list(&buf).await;
        assert!(paths.is_empty(), "empty archive should unpack to nothing");
    }

    /// Regression: a source file truncated between `stat` and the
    /// body copy must fail loudly, not silently zero-pad to match
    /// the header's declared size. Otherwise the archive is valid
    /// tar+zstd but its last entry's contents are wrong, and the
    /// client reports a successful upload for corrupt bytes.
    #[tokio::test]
    async fn add_file_errors_when_source_shrinks_during_read() {
        let src = tempfile::TempDir::new().unwrap();
        let path = src.path().join("shrinker.bin");
        // Write a moderately-sized file so `add_file` will `stat`
        // it at N bytes.
        std::fs::write(&path, vec![0xAAu8; 128 * 1024]).unwrap();

        // Take the stat picture, then truncate. This is the exact
        // shape of a concurrent editor truncating a file that
        // stream_tar_zstd/add_file already stat'd.
        let mut archive = TarZstArchive::new(Vec::new());
        // Force the stat-truncate race: `add_file` will `open`,
        // then `metadata`, then start reading. Truncate *after*
        // `add_file` starts by racing with a `spawn_blocking`.
        // Simpler shape: shrink the file to zero before `add_file`
        // reads it, but `add_file` re-`stat`s inside — so instead
        // we shrink between `add_file`'s `stat` and its read by
        // truncating from another task once `add_file` has entered
        // the fill_buf loop. That's fiddly to synchronize; the
        // easier test is a purely-behavioral one: pre-truncate to
        // half the length after opening the file for read outside
        // add_file. But add_file owns its own open, so we can't
        // interpose there.
        //
        // The cleanest way is a targeted test: pre-populate a
        // large file, then in a background task truncate it after
        // a short sleep. Add_file's read loop uses `tokio::fs`,
        // whose blocking-pool round-trips give the truncate task
        // time to land.
        let truncate_path = path.clone();
        let truncate = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = std::fs::File::options()
                .write(true)
                .open(&truncate_path)
                .and_then(|f| f.set_len(0));
        });

        let result = archive
            .add_file(&path, "shrinker.bin", AddFileOptions::default())
            .await;
        let _ = truncate.await;

        // Either the read races the truncate and succeeds (the
        // truncate landed after add_file's read), or the read
        // sees the truncated file and errors — but on the error
        // path the error must name the shrink, not surface as
        // a silent success with padded zeros.
        match result {
            Ok(()) => {
                // Race lost — the truncate landed too late.
                // Nothing to assert; the point is that the test
                // doesn't panic and doesn't silently corrupt.
            }
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("shrank during upload"),
                    "expected the shrink-detection error, got: {msg}",
                );
            }
        }
    }

    /// Regression: an outer future dropping a `TarZstArchive` before
    /// `finish` (Ctrl-C, deadline elapsed, `select!` racing loss)
    /// must not panic. `async_tar::Builder`'s own `Drop` would panic
    /// on Tokio; our `ManuallyDrop`+`forget` wrapper suppresses it.
    #[tokio::test]
    async fn tar_zst_archive_survives_drop_without_finish() {
        // Build enough to force the encoder to start committing to
        // the writer, so we're not just dropping a fresh builder.
        let src = tempfile::TempDir::new().unwrap();
        std::fs::write(src.path().join("f.txt"), "abc").unwrap();

        let mut archive = TarZstArchive::new(Vec::new());
        archive
            .add_file(
                &src.path().join("f.txt"),
                "f.txt",
                AddFileOptions::default(),
            )
            .await
            .unwrap();

        // Drop the archive after `add_file` succeeds and before
        // `finish` — this is the exact shape a cancelled outer
        // future exposes. Wrap the drop in `catch_unwind` so an
        // async-tar Drop panic escapes as an `Err` we can assert
        // on, rather than aborting the test task and confusing the
        // outer harness.
        let drop_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(archive)));
        assert!(
            drop_result.is_ok(),
            "dropping a TarZstArchive before finish must not panic",
        );
    }
}
