//! Streaming tar+zstd upload of the project directory to the daemon.

use std::path::Path;

use anyhow::Context as _;
use async_tar::Builder;
use tokio::fs;

/// Builds an in-memory tar archive of `dir`, preserving relative paths.
///
/// Symlinks are stored as symlinks. Directory entries are included so
/// empty directories survive the round-trip. Unreadable directories
/// and non-regular files (sockets, FIFOs, devices) are silently skipped.
pub async fn tar_directory(dir: &Path) -> Result<Vec<u8>, anyhow::Error> {
    let mut tar = Builder::new(Vec::new());
    let result = add_dir_entries(&mut tar, dir, "").await;
    if let Err(e) = result {
        let _ = tar.into_inner().await;
        return Err(e);
    }
    tar.into_inner().await.context("finalizing tar archive")
}

async fn add_dir_entries(
    tar: &mut Builder<Vec<u8>>,
    root: &Path,
    prefix: &str,
) -> Result<(), anyhow::Error> {
    add_dir_entries_inner(tar, root, prefix).await
}

/// Directories always skipped during upload. A proper .gitignore
/// implementation is tracked as a follow-up on #263.
const DEFAULT_EXCLUDED_DIRS: &[&str] = &[".git", "target", "node_modules"];

fn is_default_excluded(name: &str) -> bool {
    DEFAULT_EXCLUDED_DIRS.contains(&name)
}

async fn file_type_will_be_dir(entry: &tokio::fs::DirEntry, entry_path: &std::path::Path) -> bool {
    match entry.file_type().await {
        Ok(t) => t.is_dir(),
        Err(_) => entry_path.is_dir(),
    }
}

fn add_dir_entries_inner<'a>(
    tar: &'a mut Builder<Vec<u8>>,
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

            // Skip common heavy/irrelevant directories. A proper .gitignore
            // implementation is tracked as a follow-up on #263.
            if file_type_will_be_dir(&entry, &entry_path).await && is_default_excluded(&name_str) {
                continue;
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

    /// Unpacks a raw tar archive into a tempdir and returns the list of
    /// all file paths (relative) found by walking the unpacked tree.
    async fn unpack_and_list(tar_bytes: &[u8]) -> Vec<String> {
        let out = tempfile::TempDir::new().unwrap();
        let archive = async_tar::Archive::new(tar_bytes);
        archive.unpack(out.path().to_path_buf()).await.unwrap();

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
        let mut paths = Vec::new();
        walk(out.path(), out.path(), &mut paths);
        paths
    }

    #[tokio::test]
    async fn tar_skips_unix_sockets() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello").unwrap();
        let _socket = UnixListener::bind(dir.path().join("sock")).unwrap();

        let tar = tar_directory(dir.path()).await.unwrap();
        let paths = unpack_and_list(&tar).await;

        assert!(
            paths.iter().any(|p| p == "hello.txt"),
            "hello.txt should be in the archive"
        );
        assert!(!paths.iter().any(|p| p == "sock"), "sock should be skipped");
    }

    #[tokio::test]
    async fn tar_skips_permission_denied_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("readable.txt"), "ok").unwrap();

        let restricted = dir.path().join("restricted");
        std::fs::create_dir(&restricted).unwrap();
        std::fs::write(restricted.join("secret.txt"), "secret").unwrap();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();

        let tar = tar_directory(dir.path()).await.unwrap();

        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o755)).ok();

        let paths = unpack_and_list(&tar).await;
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
    async fn tar_includes_regular_files_dirs_and_symlinks() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "content").unwrap();
        std::fs::create_dir_all(dir.path().join("subdir")).unwrap();
        std::fs::write(dir.path().join("subdir/nested.txt"), "nested").unwrap();
        std::os::unix::fs::symlink("file.txt", dir.path().join("link")).unwrap();

        let tar = tar_directory(dir.path()).await.unwrap();
        let paths = unpack_and_list(&tar).await;

        assert!(paths.iter().any(|p| p == "file.txt"), "file.txt missing");
        assert!(
            paths.iter().any(|p| p == "subdir/nested.txt"),
            "nested.txt missing"
        );
        assert!(paths.iter().any(|p| p == "link"), "symlink missing");
    }

    #[tokio::test]
    async fn tar_does_not_follow_symlinks_to_external_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let external = tempfile::TempDir::new().unwrap();
        std::fs::write(external.path().join("secret"), "sensitive").unwrap();

        // Create a symlink pointing outside the project dir.
        std::os::unix::fs::symlink(external.path().join("secret"), dir.path().join("escape"))
            .unwrap();
        std::fs::write(dir.path().join("safe.txt"), "safe").unwrap();

        let tar = tar_directory(dir.path()).await.unwrap();

        // Unpack into a tempdir and verify the symlink was stored as a
        // symlink (not the external file's contents).
        let out = tempfile::TempDir::new().unwrap();
        let archive = async_tar::Archive::new(&tar[..]);
        archive.unpack(out.path().to_path_buf()).await.unwrap();

        let escape_path = out.path().join("escape");
        assert!(
            escape_path.is_symlink(),
            "escape should be a symlink, not a copied file"
        );
        // Verify it still points to the external path, not the content.
        let target = std::fs::read_link(&escape_path).unwrap();
        assert_eq!(target, external.path().join("secret"));

        // The external file's content should NOT have been copied.
        assert!(
            !std::fs::exists(escape_path.join("secret")).unwrap_or(false),
            "should not have followed the symlink"
        );

        // safe.txt should be present.
        assert!(out.path().join("safe.txt").is_file());
    }

    #[tokio::test]
    async fn tar_excludes_default_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "keep").unwrap();
        std::fs::create_dir_all(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("target/binary.o"), "binary").unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "gitconfig").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules/lib.js"), "lib").unwrap();

        let tar = tar_directory(dir.path()).await.unwrap();
        let paths = unpack_and_list(&tar).await;

        assert!(
            paths.iter().any(|p| p == "keep.txt"),
            "keep.txt should be uploaded"
        );
        assert!(
            !paths.iter().any(|p| p.contains("target/")),
            "target/ should be excluded"
        );
        assert!(
            !paths.iter().any(|p| p.contains(".git/")),
            ".git/ should be excluded"
        );
        assert!(
            !paths.iter().any(|p| p.contains("node_modules/")),
            "node_modules/ should be excluded"
        );
    }
}
