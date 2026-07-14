//! Streaming tar+zstd upload of the project directory to the daemon.

use std::path::Path;

use anyhow::Context as _;
use async_tar::Builder;
use tokio::fs;

/// Builds an in-memory tar archive of `dir`, preserving relative paths.
///
/// Symlinks are stored as symlinks. Directory entries are included so
/// empty directories survive the round-trip.
pub async fn tar_directory(dir: &Path) -> Result<Vec<u8>, anyhow::Error> {
    let mut tar = Builder::new(Vec::new());
    add_dir_entries(&mut tar, dir, "").await?;
    let bytes = tar.into_inner().await.context("finalizing tar archive")?;
    Ok(bytes)
}

fn add_dir_entries<'a>(
    tar: &'a mut Builder<Vec<u8>>,
    root: &'a Path,
    prefix: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = fs::read_dir(root)
            .await
            .with_context(|| format!("reading directory {}", root.display()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .context("reading directory entry")?
        {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let entry_path = entry.path();
            let archive_path = if prefix.is_empty() {
                name_str.to_string()
            } else {
                format!("{prefix}/{name_str}")
            };

            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("getting file type for {}", entry_path.display()))?;

            if file_type.is_dir() {
                let mut header = async_tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o755);
                header.set_entry_type(async_tar::EntryType::Directory);
                header.set_cksum();
                tar.append_data(&mut header, &archive_path, &[][..])
                    .await
                    .with_context(|| format!("adding directory {archive_path}"))?;

                add_dir_entries(tar, &entry_path, &archive_path).await?;
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
            } else {
                let mut file = fs::File::open(&entry_path)
                    .await
                    .with_context(|| format!("opening {}", entry_path.display()))?;
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
        }

        Ok(())
    })
}
