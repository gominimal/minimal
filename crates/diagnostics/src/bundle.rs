//! Tar+zstd writer for diagnostic bundles.
//!
//! One writer, two modes. File-backed mode (`create`) is for a CLI writing a
//! local artifact: entries land under a single top-level directory (the
//! bundle name) so extraction is tidy, and the file is created owner-only.
//! Stream mode (`stream`) is for a daemon writing through a pipe: entries sit
//! at the archive top level (rootless — nested-bundle consumers do exact-key
//! lookups). Both modes append the manifest last from the accumulated record,
//! so even a run whose collectors all failed produces a valid archive with a
//! complete error report.

use std::path::Path;

use anyhow::Context as _;
use async_compression::tokio::write::ZstdEncoder;
use async_tar::{Builder, EntryType, Header};
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::manifest::{CollectedEntry, CollectorError, Manifest, Redaction, SkippedEntry};

/// Default per-file tail cap for bundled logs.
pub const LOG_TAIL_CAP: u64 = 5 * 1024 * 1024;

mod sealed {
    pub trait Sealed {}
    impl Sealed for tokio::fs::File {}
    impl Sealed for tokio::io::DuplexStream {}
}

/// A writer a [`BundleWriter`] can finalize.
///
/// Sealed: the finalize semantics are mode decisions owned by this crate.
/// `Sync` is load-bearing — `async_tar::Builder` requires it, which is why a
/// bundle can never wrap a non-`Sync` transport writer directly (daemons pump
/// through a [`tokio::io::DuplexStream`] instead).
pub trait BundleSink: AsyncWrite + Unpin + Send + Sync + sealed::Sealed {
    #[doc(hidden)]
    fn finalize(self) -> impl Future<Output = std::io::Result<()>> + Send
    where
        Self: Sized;
}

impl BundleSink for tokio::fs::File {
    /// Durability matters for a file artifact: flush and fsync.
    async fn finalize(mut self) -> std::io::Result<()> {
        self.flush().await?;
        self.sync_all().await
    }
}

impl BundleSink for tokio::io::DuplexStream {
    /// A pipe has no durability to guarantee; flush and half-close so the
    /// reading side sees EOF.
    async fn finalize(mut self) -> std::io::Result<()> {
        self.flush().await?;
        self.shutdown().await
    }
}

pub struct BundleWriter<W: BundleSink = tokio::fs::File> {
    tar: Builder<ZstdEncoder<W>>,
    /// Top-level directory for every entry; `None` in stream mode (rootless).
    root: Option<String>,
    /// Producer version recorded in the manifest — the crate is app-agnostic,
    /// so the caller supplies it.
    version: String,
    collected: Vec<CollectedEntry>,
    skipped: Vec<SkippedEntry>,
    errors: Vec<CollectorError>,
}

impl BundleWriter<tokio::fs::File> {
    /// Creates the output file at `out_path`; `root` becomes the single
    /// top-level directory inside the archive, and `version` is recorded
    /// in the manifest.
    pub async fn create(out_path: &Path, root: &str, version: &str) -> Result<Self, anyhow::Error> {
        // 0600: the bundle carries unredacted log tails, session records, and
        // process state, and lands in the cwd by default — not world-readable.
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let file = opts
            .open(out_path)
            .await
            .with_context(|| format!("creating {}", out_path.display()))?;
        // mode() only applies when create() makes the file; a pre-existing
        // 0644 file keeps its bits, so pin them explicitly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .await
                .with_context(|| format!("securing {}", out_path.display()))?;
        }
        Ok(Self::new(file, Some(root.to_string()), version))
    }
}

impl<W: BundleSink> BundleWriter<W> {
    /// Streams the archive through `writer` with entries at the top level
    /// (no root directory) — the daemon-side mode, where the nested bundle's
    /// consumers do exact-key lookups like `meta.json`.
    pub fn stream(writer: W, version: &str) -> Self {
        Self::new(writer, None, version)
    }

    fn new(writer: W, root: Option<String>, version: &str) -> Self {
        Self {
            tar: Builder::new(ZstdEncoder::new(writer)),
            root,
            version: version.to_string(),
            collected: Vec::new(),
            skipped: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Adds `bytes` at `path` (bundle-relative) and records it in the
    /// manifest with the given redaction level.
    pub async fn add_bytes(
        &mut self,
        path: &str,
        bytes: &[u8],
        redaction: Redaction,
    ) -> Result<(), anyhow::Error> {
        self.append(path, bytes).await?;
        self.collected.push(CollectedEntry {
            path: path.to_string(),
            redaction,
            bytes: bytes.len() as u64,
        });
        Ok(())
    }

    /// Copies up to the last `cap` bytes of `src` to `path`. Files over the
    /// cap are recorded as tail-capped; smaller ones as unredacted copies.
    pub async fn add_file_tail(
        &mut self,
        path: &str,
        src: &Path,
        cap: u64,
    ) -> Result<(), anyhow::Error> {
        let (mut file, meta) = open_regular_nofollow(src).await?;
        let len = meta.len();
        let capped = len > cap;
        if capped {
            use tokio::io::AsyncSeekExt as _;
            file.seek(std::io::SeekFrom::End(-(cap as i64)))
                .await
                .with_context(|| format!("seeking {}", src.display()))?;
        }
        // Bound the read at the reader, not just the seek: the file may be a
        // live log appended to between the stat and the read.
        let mut contents = Vec::with_capacity(len.min(cap) as usize);
        (&mut file)
            .take(cap)
            .read_to_end(&mut contents)
            .await
            .with_context(|| format!("reading {}", src.display()))?;
        let redaction = if capped {
            Redaction::TailCapped
        } else {
            Redaction::None
        };
        self.add_bytes(path, &contents, redaction).await
    }

    /// Records something deliberately withheld from the bundle.
    pub fn skip(&mut self, what: impl Into<String>, reason: impl Into<String>) {
        self.skipped.push(SkippedEntry {
            what: what.into(),
            reason: reason.into(),
        });
    }

    /// Records a failed collector; the bundle carries on without it.
    pub fn error(
        &mut self,
        collector: impl Into<String>,
        error: impl std::fmt::Display,
        duration: std::time::Duration,
    ) {
        self.errors.push(CollectorError {
            collector: collector.into(),
            error: error.to_string(),
            duration_ms: duration.as_millis() as u64,
        });
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn entry_count(&self) -> usize {
        self.collected.len()
    }

    /// Writes `manifest.json` from the accumulated record and finalizes the
    /// archive. Must be the last call.
    pub async fn finish(
        mut self,
        created_at: chrono::DateTime<chrono::Utc>,
        duration: std::time::Duration,
    ) -> Result<(), anyhow::Error> {
        let manifest = Manifest {
            schema_version: crate::manifest::SCHEMA_VERSION,
            created_at,
            version: std::mem::take(&mut self.version),
            duration_ms: duration.as_millis() as u64,
            collected: std::mem::take(&mut self.collected),
            skipped: std::mem::take(&mut self.skipped),
            errors: std::mem::take(&mut self.errors),
        };
        let json = serde_json::to_vec_pretty(&manifest).context("serializing manifest")?;
        self.append("manifest.json", &json).await?;

        let mut encoder = self
            .tar
            .into_inner()
            .await
            .context("finalizing tar archive")?;
        encoder.shutdown().await.context("flushing zstd encoder")?;
        encoder
            .into_inner()
            .finalize()
            .await
            .context("finalizing bundle writer")?;
        Ok(())
    }

    async fn append(&mut self, path: &str, bytes: &[u8]) -> Result<(), anyhow::Error> {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        let full = match &self.root {
            Some(root) => format!("{root}/{path}"),
            None => path.to_string(),
        };
        self.tar
            .append_data(&mut header, &full, bytes)
            .await
            .with_context(|| format!("adding {full}"))
    }
}

/// Opens `src` for reading without following symlinks and verifies on the
/// descriptor that it is a regular file — the shared no-follow discipline
/// for every content read that ends up in a bundle.
///
/// A symlink planted in a tool-owned dir must not steer an unrelated target
/// (a host key, another user's log) into a bundle the user then shares.
/// O_NOFOLLOW refuses the link at open time — no check-then-open window to
/// race — and the fstat rejects directories and devices, doubling as the
/// symlink guard where O_NOFOLLOW is unavailable. (It guards the final
/// component only; intermediate directories are the tool's own, per the
/// threat model.)
pub async fn open_regular_nofollow(
    src: &Path,
) -> Result<(tokio::fs::File, std::fs::Metadata), anyhow::Error> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    let file = opts
        .open(src)
        .await
        .with_context(|| format!("opening {}", src.display()))?;
    let meta = file
        .metadata()
        .await
        .with_context(|| format!("statting {}", src.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file", src.display());
    }
    Ok((file, meta))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Decodes a bundle and returns its entries in archive order as
    /// `(archive path, contents)`.
    pub(crate) async fn bundle_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        use tokio_stream::StreamExt as _;
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(bytes);
        let archive = async_tar::Archive::new(decoder);
        let mut out = Vec::new();
        let mut entries = archive.entries().unwrap();
        while let Some(entry) = entries.next().await {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).await.unwrap();
            out.push((path, contents));
        }
        out
    }

    /// Unpacks a bundle file and returns `bundle-relative path -> contents`,
    /// stripping `root/` when given.
    pub(crate) async fn unpack_bundle(path: &Path, root: &str) -> BTreeMap<String, Vec<u8>> {
        let bytes = tokio::fs::read(path).await.unwrap();
        let prefix = if root.is_empty() {
            String::new()
        } else {
            format!("{root}/")
        };
        bundle_entries(&bytes)
            .await
            .into_iter()
            .map(|(p, c)| (p.strip_prefix(&prefix).unwrap_or(&p).to_string(), c))
            .collect()
    }

    #[tokio::test]
    async fn bundle_round_trips_with_manifest_last() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("b.tar.zst");

        let mut w = BundleWriter::create(&out, "minimal-diag-test", "test-version")
            .await
            .unwrap();
        w.add_bytes("host/system.json", b"{}", Redaction::None)
            .await
            .unwrap();
        w.skip("config/client.key", "private key material");
        w.error(
            "net.listening",
            "ss not found",
            std::time::Duration::from_millis(3),
        );
        w.finish(chrono::Utc::now(), std::time::Duration::from_secs(1))
            .await
            .unwrap();

        let bytes = tokio::fs::read(&out).await.unwrap();
        let entries = bundle_entries(&bytes).await;
        assert_eq!(
            entries.last().unwrap().0,
            "minimal-diag-test/manifest.json",
            "file-backed manifest lands last, under the root"
        );

        let files = unpack_bundle(&out, "minimal-diag-test").await;
        assert_eq!(files["host/system.json"], b"{}");

        let manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(manifest["schema_version"], 1);
        assert_eq!(manifest["version"], "test-version");
        assert_eq!(manifest["collected"][0]["path"], "host/system.json");
        assert_eq!(manifest["collected"][0]["redaction"], "none");
        assert_eq!(manifest["skipped"][0]["what"], "config/client.key");
        assert_eq!(manifest["errors"][0]["collector"], "net.listening");
    }

    #[tokio::test]
    async fn stream_mode_is_rootless_and_matches_file_mode() {
        // File mode.
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("f.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        w.add_bytes("meta.json", b"{}", Redaction::None)
            .await
            .unwrap();
        let created = chrono::Utc::now();
        w.finish(created, std::time::Duration::ZERO).await.unwrap();
        let file_entries = bundle_entries(&tokio::fs::read(&out).await.unwrap()).await;

        // Stream mode through a duplex pipe (the daemon shape).
        let (tx, mut rx) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            rx.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let mut w = BundleWriter::stream(tx, "v");
        w.add_bytes("meta.json", b"{}", Redaction::None)
            .await
            .unwrap();
        w.finish(created, std::time::Duration::ZERO).await.unwrap();
        let stream_entries = bundle_entries(&reader.await.unwrap()).await;

        // Rootless: exact top-level keys, manifest last.
        assert_eq!(stream_entries[0].0, "meta.json");
        assert_eq!(stream_entries.last().unwrap().0, "manifest.json");
        // Identical modulo the root prefix.
        let stripped: Vec<_> = file_entries
            .iter()
            .map(|(p, c)| (p.strip_prefix("r/").unwrap().to_string(), c.clone()))
            .collect();
        assert_eq!(stripped, stream_entries);
    }

    #[tokio::test]
    async fn add_file_tail_caps_large_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let big = tmp.path().join("big.log");
        std::fs::write(&big, [b'a'; 100].as_slice()).unwrap();
        let out = tmp.path().join("b.tar.zst");

        let mut w = BundleWriter::create(&out, "r", "test-version")
            .await
            .unwrap();
        w.add_file_tail("logs/big.log", &big, 10).await.unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack_bundle(&out, "r").await;
        assert_eq!(files["logs/big.log"].len(), 10);
        let manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(manifest["collected"][0]["redaction"], "tail-capped");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn add_file_tail_rejects_symlinks_at_open() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target.log");
        std::fs::write(&target, "sensitive").unwrap();
        let link = tmp.path().join("minimald.log.evil");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let out = tmp.path().join("b.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        let err = w.add_file_tail("logs/evil", &link, 1024).await.unwrap_err();
        assert!(
            err.to_string().contains("opening"),
            "symlink must be refused at open time, got: {err:#}"
        );
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bundle_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("b.tar.zst");
        let w = BundleWriter::create(&out, "r", "v").await.unwrap();
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
    }
}
