//! Tar+zstd writer for the diagnostic bundle.
//!
//! Unlike the workspace upload ([`crate::file_upload`]) this writes to a local
//! file, which is `Sync`, so the tar builder writes straight through the zstd
//! encoder with no duplex pipe. Every entry lands under a single top-level
//! directory (the bundle name) so extraction is tidy, and the manifest is
//! appended last from the accumulated record — even a run whose collectors all
//! failed produces a valid archive with a complete error report.

use std::path::Path;

use anyhow::Context as _;
use async_compression::tokio::write::ZstdEncoder;
use async_tar::{Builder, EntryType, Header};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::manifest::{CollectedEntry, CollectorError, Manifest, Redaction, SkippedEntry};

/// Default per-file tail cap for bundled logs.
pub const LOG_TAIL_CAP: u64 = 5 * 1024 * 1024;

pub struct BundleWriter {
    tar: Builder<ZstdEncoder<tokio::fs::File>>,
    /// Bundle name, used as the top-level directory for every entry.
    root: String,
    collected: Vec<CollectedEntry>,
    skipped: Vec<SkippedEntry>,
    errors: Vec<CollectorError>,
}

impl BundleWriter {
    /// Creates the output file at `out_path`; `root` becomes the single
    /// top-level directory inside the archive.
    pub async fn create(out_path: &Path, root: &str) -> Result<Self, anyhow::Error> {
        let file = tokio::fs::File::create(out_path)
            .await
            .with_context(|| format!("creating {}", out_path.display()))?;
        Ok(Self {
            tar: Builder::new(ZstdEncoder::new(file)),
            root: root.to_string(),
            collected: Vec::new(),
            skipped: Vec::new(),
            errors: Vec::new(),
        })
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
        let mut file = tokio::fs::File::open(src)
            .await
            .with_context(|| format!("opening {}", src.display()))?;
        let len = file
            .metadata()
            .await
            .with_context(|| format!("statting {}", src.display()))?
            .len();
        let capped = len > cap;
        if capped {
            use tokio::io::AsyncSeekExt as _;
            file.seek(std::io::SeekFrom::End(-(cap as i64)))
                .await
                .with_context(|| format!("seeking {}", src.display()))?;
        }
        let mut contents = Vec::with_capacity(len.min(cap) as usize);
        file.read_to_end(&mut contents)
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
            schema_version: super::manifest::SCHEMA_VERSION,
            created_at,
            cli_version: env!("LONG_VERSION").to_string(),
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
        let mut file = encoder.into_inner();
        file.flush().await.context("flushing bundle file")?;
        file.sync_all().await.context("syncing bundle file")?;
        Ok(())
    }

    async fn append(&mut self, path: &str, bytes: &[u8]) -> Result<(), anyhow::Error> {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        let full = format!("{}/{path}", self.root);
        self.tar
            .append_data(&mut header, &full, bytes)
            .await
            .with_context(|| format!("adding {full}"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Unpacks a bundle file and returns `bundle-relative path -> contents`.
    pub(crate) async fn unpack_bundle(path: &Path, root: &str) -> BTreeMap<String, Vec<u8>> {
        let bytes = tokio::fs::read(path).await.unwrap();
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&bytes[..]);
        let out = tempfile::TempDir::new().unwrap();
        async_tar::Archive::new(decoder)
            .unpack(out.path().to_path_buf())
            .await
            .unwrap();

        let base = out.path().join(root);
        let mut files = BTreeMap::new();
        for entry in walkdir(&base) {
            let rel = entry.strip_prefix(&base).unwrap().to_string_lossy().into();
            files.insert(rel, std::fs::read(&entry).unwrap());
        }
        files
    }

    fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walkdir(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    #[tokio::test]
    async fn bundle_round_trips_with_manifest_last() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("b.tar.zst");

        let mut w = BundleWriter::create(&out, "minimal-diag-test")
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

        let files = unpack_bundle(&out, "minimal-diag-test").await;
        assert_eq!(files["host/system.json"], b"{}");

        let manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(manifest["schema_version"], 1);
        assert_eq!(manifest["collected"][0]["path"], "host/system.json");
        assert_eq!(manifest["collected"][0]["redaction"], "none");
        assert_eq!(manifest["skipped"][0]["what"], "config/client.key");
        assert_eq!(manifest["errors"][0]["collector"], "net.listening");
    }

    #[tokio::test]
    async fn add_file_tail_caps_large_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let big = tmp.path().join("big.log");
        std::fs::write(&big, [b'a'; 100].as_slice()).unwrap();
        let out = tmp.path().join("b.tar.zst");

        let mut w = BundleWriter::create(&out, "r").await.unwrap();
        w.add_file_tail("logs/big.log", &big, 10).await.unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack_bundle(&out, "r").await;
        assert_eq!(files["logs/big.log"].len(), 10);
        let manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(manifest["collected"][0]["redaction"], "tail-capped");
    }
}
