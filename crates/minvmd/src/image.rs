//! `image::ensure_image` — fetch the rootfs and verify its SHA-256 digest.
//!
//! Uses `curl` for the download and `sha256sum` (Linux) / `shasum -a 256`
//! (macOS) for digest verification. Both tools are assumed to be on `$PATH`.
//!
//! Environment variables:
//! - `MINVMD_IMAGE_URL`    (required) — URL of the rootfs archive.
//! - `MINVMD_IMAGE_SHA256` (required) — hex SHA-256 of the archive.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use sessions::paths::HostAbsPath;

use crate::config::Config;
use crate::error::UserFacing;

/// Ensure the rootfs image and the qcow2 state disk are present in `vm_dir`.
///
/// - Downloads `$MINVMD_IMAGE_URL` to `vm_dir/rootfs.raw` if the file is
///   absent or its SHA-256 does not match `$MINVMD_IMAGE_SHA256`.
/// - Removes the partial file and returns an error on digest mismatch.
/// - Creates `vm_dir/state.qcow2` via `qemu-img create` if absent; its size
///   is `config.state_size_gib` GiB.
pub async fn ensure_image(config: &Config, vm_dir: &Path) -> anyhow::Result<()> {
    let image_url = std::env::var("MINVMD_IMAGE_URL").map_err(|_| {
        anyhow::Error::from(UserFacing::new(
            "MINVMD_IMAGE_URL is not set; obtain the image URL from \
             https://github.com/gominimal/minimal-vm-image and export it \
             before running `minvmd up`.",
        ))
    })?;
    let image_sha256 = std::env::var("MINVMD_IMAGE_SHA256").map_err(|_| {
        anyhow::Error::from(UserFacing::new(
            "MINVMD_IMAGE_SHA256 is not set; obtain the expected digest from \
             https://github.com/gominimal/minimal-vm-image and export it \
             before running `minvmd up`.",
        ))
    })?;

    tokio::fs::create_dir_all(vm_dir)
        .await
        .with_context(|| format!("create vm dir {}", vm_dir.display()))?;

    let rootfs = vm_dir.join("rootfs.raw");
    fetch_and_verify(&rootfs, &image_url, &image_sha256).await?;

    let qcow2 = vm_dir.join("state.qcow2");
    if !qcow2.exists() {
        create_qcow2(&qcow2, config.state_size_gib).await?;
    }

    Ok(())
}

/// Download `url` to `dest` (via `curl`), then verify the SHA-256 hex digest
/// matches `expected_hex`. Removes `dest` and returns an error on mismatch.
pub(crate) async fn fetch_and_verify(
    dest: &Path,
    url: &str,
    expected_hex: &str,
) -> anyhow::Result<()> {
    // Skip the download when the existing file already matches.
    if dest.exists() {
        match file_sha256(dest).await {
            Ok(actual) if actual == expected_hex.to_ascii_lowercase() => return Ok(()),
            _ => {
                // File present but digest wrong — remove it and re-download.
                let _ = tokio::fs::remove_file(dest).await;
            }
        }
    }

    download(dest, url).await?;

    let actual = file_sha256(dest)
        .await
        .with_context(|| format!("sha256 of {}", dest.display()))?;

    if actual != expected_hex.to_ascii_lowercase() {
        let _ = tokio::fs::remove_file(dest).await;
        return Err(anyhow::anyhow!(
            "SHA-256 mismatch: expected {expected_hex}, got {actual}"
        ));
    }

    Ok(())
}

/// Download `url` to `dest` via `curl`.
async fn download(dest: &Path, url: &str) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("curl")
        .args(["-fsSL", url, "-o", &dest.to_string_lossy()])
        .status()
        .await
        .context("run curl")?;
    if !status.success() {
        anyhow::bail!("curl exited with {status} fetching {url}");
    }
    Ok(())
}

/// Compute the SHA-256 hex digest of a file using the system `sha256sum`
/// (Linux) or `shasum -a 256` (macOS).
async fn file_sha256(path: &Path) -> anyhow::Result<String> {
    // Prefer `sha256sum`; fall back to `shasum -a 256` on macOS.
    let output = if cfg!(target_os = "macos") {
        tokio::process::Command::new("shasum")
            .args(["-a", "256", &path.to_string_lossy()])
            .output()
            .await
            .context("run shasum")?
    } else {
        tokio::process::Command::new("sha256sum")
            .arg(path)
            .output()
            .await
            .context("run sha256sum")?
    };

    if !output.status.success() {
        anyhow::bail!(
            "sha256 tool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Both `sha256sum` and `shasum` output `<hex>  <filename>`.
    let hex = stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("unexpected sha256 output: {stdout}"))?;
    Ok(hex.to_ascii_lowercase())
}

async fn create_qcow2(path: &Path, size_gib: u32) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("qemu-img")
        .args([
            "create",
            "-f",
            "qcow2",
            &path.to_string_lossy(),
            &format!("{size_gib}G"),
        ])
        .status()
        .await
        .context("run qemu-img")?;
    if !status.success() {
        anyhow::bail!("qemu-img create failed with {status}");
    }
    Ok(())
}

/// Return the canonical vm dir (`$MINIMAL_HOME/vm/`) for use by callers that
/// do not want to re-derive the path.
// Only the macOS `up` path calls this; on the Linux shim build it has no
// caller and no test exercises it, so allow dead code off-macOS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn default_vm_dir() -> anyhow::Result<HostAbsPath> {
    let home = std::env::var_os("MINIMAL_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".minimal")))
        .ok_or_else(|| anyhow::anyhow!("cannot determine MINIMAL_HOME"))?;
    let vm_dir = home.join("vm");
    let utf8 = camino::Utf8PathBuf::from_path_buf(vm_dir)
        .map_err(|p| anyhow::anyhow!("vm dir is not valid UTF-8: {}", p.display()))?;
    // `$MINIMAL_HOME` / `~/.minimal` is always absolute, so this is effectively
    // infallible; surface a clear error if that invariant is ever violated.
    HostAbsPath::try_new(utf8).context("vm dir must be absolute")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{serial_test::serial, with_isolated_home};

    /// Write `content` to a temp file, compute its SHA-256 with the system tool,
    /// and return the hex string. Uses a synchronous helper for test setup.
    fn sha256_of(content: &[u8]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tmp");
        std::fs::write(&p, content).unwrap();
        let out = std::process::Command::new("sha256sum")
            .arg(&p)
            .output()
            .unwrap_or_else(|_| {
                // macOS fallback
                std::process::Command::new("shasum")
                    .args(["-a", "256"])
                    .arg(&p)
                    .output()
                    .unwrap()
            });
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_ascii_lowercase()
    }

    #[test]
    #[serial]
    fn fetch_and_verify_succeeds_on_matching_sha256() {
        with_isolated_home(|home| {
            // Write a fixture file that `MINVMD_IMAGE_URL` will point at via file://.
            let fixture = home.join("fixture.raw");
            let content = b"fake rootfs content";
            std::fs::write(&fixture, content).unwrap();
            let expected_sha = sha256_of(content);

            let dest_dir = home.join("vm");
            std::fs::create_dir_all(&dest_dir).unwrap();
            let dest = dest_dir.join("rootfs.raw");

            let url = format!("file://{}", fixture.display());

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    fetch_and_verify(&dest, &url, &expected_sha)
                        .await
                        .expect("fetch_and_verify should succeed on matching SHA-256");
                    assert!(dest.exists(), "rootfs.raw must exist after success");

                    // Idempotent: second call with same digest must also succeed.
                    fetch_and_verify(&dest, &url, &expected_sha)
                        .await
                        .expect("second fetch_and_verify should succeed");
                });
        });
    }

    #[test]
    #[serial]
    fn fetch_and_verify_fails_and_removes_file_on_bad_sha256() {
        with_isolated_home(|home| {
            let fixture = home.join("fixture.raw");
            std::fs::write(&fixture, b"fake rootfs content").unwrap();

            let dest_dir = home.join("vm");
            std::fs::create_dir_all(&dest_dir).unwrap();
            let dest = dest_dir.join("rootfs.raw");

            let bad_sha = "0".repeat(64);
            let url = format!("file://{}", fixture.display());

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let err = fetch_and_verify(&dest, &url, &bad_sha).await;
                    assert!(err.is_err(), "should fail on digest mismatch");
                    assert!(!dest.exists(), "partial file must be removed on mismatch");
                });
        });
    }

    #[test]
    #[serial]
    fn ensure_image_errors_when_url_unset() {
        with_isolated_home(|home| {
            // SAFETY: serialised by `#[serial]` (via with_isolated_home) so no
            // other test thread mutates env concurrently.
            unsafe {
                std::env::remove_var("MINVMD_IMAGE_URL");
                std::env::remove_var("MINVMD_IMAGE_SHA256");
            }

            let vm_dir = home.join("vm");
            let config = Config::default();

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let err = ensure_image(&config, &vm_dir).await;
                    assert!(err.is_err(), "expect error when MINVMD_IMAGE_URL is unset");
                    let msg = format!("{:#}", err.unwrap_err());
                    assert!(
                        msg.contains("gominimal/minimal-vm-image"),
                        "error should reference minimal-vm-image, got: {msg}"
                    );
                });
        });
    }
}
