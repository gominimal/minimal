use anyhow::{Result, bail};
use google_cloud_storage::client::Storage;
use sha2::{Digest, Sha256};

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RemoteStorage {
    client: Storage,
    cache_dir: PathBuf,
}

impl RemoteStorage {
    #[tracing::instrument]
    pub async fn new() -> Result<Self> {
        // TODO: This is temporary, remove this after october
        if fs::exists(dirs::cache_dir().unwrap().join("minimal-fetches"))? {
            fs::remove_dir_all(dirs::cache_dir().unwrap().join("minimal-fetches"))?;
        }

        let cache_dir = {
            let dir = dirs::cache_dir().unwrap().join("minimal-dl");
            match fs::create_dir_all(&dir) {
                Ok(_) => {}
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        panic!("failed to create build fetch-cache dir: {}", e);
                    }
                }
            };
            dir
        };

        let client = Storage::builder().build().await?;
        Ok(Self { client, cache_dir })
    }

    fn sha_dir(&self, sha256: &str) -> Result<PathBuf> {
        if sha256.contains("/") {
            bail!("SHA256 had a slash in it");
        }

        let dir_path = self.cache_dir.join(sha256);
        match fs::metadata(&dir_path) {
            Ok(stat) => {
                if stat.is_dir() {
                    Ok(dir_path)
                } else {
                    bail!(
                        "unexpected: {} is not a directory",
                        dir_path.to_str().unwrap()
                    )
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    fs::create_dir(&dir_path)?;
                    Ok(dir_path)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    #[tracing::instrument]
    pub async fn download_https_with_verification_and_caching(
        &self,
        url: &str,
        sha256: &str,
    ) -> Result<PathBuf> {
        if sha256.contains("/") {
            bail!("SHA256 had a slash in it");
        }
        let filename = &url[url.rfind("/").unwrap() + 1..];
        let cached_path = self.sha_dir(sha256)?.join(filename);

        // File exists in cache, try and use it if the hash matches
        if fs::exists(&cached_path)? {
            let computed_hash = {
                let mut f = fs::File::open(&cached_path)?;
                let mut hasher = Sha256::new();
                std::io::copy(&mut f, &mut hasher)?;

                hasher.finalize()
            };

            if hex::encode(computed_hash) == sha256 {
                return Ok(cached_path);
            } else {
                fs::remove_file(&cached_path)?;
            }
        }

        // Otherwise download, writing to the file and hashing as we go
        let mut hasher = Sha256::new();
        {
            let mut f = fs::File::create(&cached_path)?;
            let mut res = reqwest::get(url).await?;

            let mut w = Tee::new(&mut f, &mut hasher);
            while let Some(chunk) = res.chunk().await? {
                w.write_all(&chunk).unwrap();
            }
            f.sync_all()?;
        }

        let computed_hash = hasher.finalize();
        let computed_hex = hex::encode(computed_hash);

        if computed_hex != sha256 {
            fs::remove_file(&cached_path).ok(); // ignore error, best effort
            bail!(
                "SHA256 mismatch for {}: expected {}, got {}",
                url,
                sha256,
                computed_hex
            );
        }
        Ok(cached_path)
    }

    #[tracing::instrument]
    pub async fn download_with_verification_and_caching(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
    ) -> Result<PathBuf> {
        if sha256.contains("/") {
            bail!("SHA256 had a slash in it");
        }
        let filename = match file.rfind("/") {
            Some(idx) => &file[idx + 1..],
            None => file,
        };
        let cached_path = self.sha_dir(sha256)?.join(filename);

        // File exists in cache, try and use it if the hash matches
        if fs::exists(&cached_path)? {
            let computed_hash = {
                let mut f = fs::File::open(&cached_path)?;
                let mut hasher = Sha256::new();
                std::io::copy(&mut f, &mut hasher)?;

                hasher.finalize()
            };

            if hex::encode(computed_hash) == sha256 {
                return Ok(cached_path);
            } else {
                fs::remove_file(&cached_path)?;
            }
        }

        // Otherwise download, writing to the file and hashing as we go
        let mut hasher = Sha256::new();
        {
            let mut f = fs::File::create(&cached_path)?;
            self.download(bucket_id.clone(), file, &mut Tee::new(&mut f, &mut hasher))
                .await?;
            f.sync_data()?;
        }
        let computed_hash = hasher.finalize();
        let computed_hex = hex::encode(computed_hash);

        if computed_hex != sha256 {
            fs::remove_file(&cached_path).ok(); // ignore error, best effort
            bail!(
                "SHA256 mismatch for {}//{}: expected {}, got {}",
                bucket_id,
                file,
                sha256,
                computed_hex
            );
        }

        Ok(cached_path)
    }

    #[tracing::instrument]
    pub async fn download<B: Write + std::fmt::Debug>(
        &self,
        bucket_id: String,
        file: &str,
        into: &mut B,
    ) -> Result<()> {
        let mut reader = self
            .client
            .read_object(format!("projects/_/buckets/{bucket_id}"), file)
            .send()
            .await?;
        while let Some(chunk) = reader.next().await.transpose()? {
            into.write(&chunk)?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(data))]
    pub async fn upload(&self, bucket_id: &str, file_path: &str, data: &[u8]) -> Result<()> {
        let bytes_data = bytes::Bytes::copy_from_slice(data);
        let _response = self
            .client
            .write_object(
                format!("projects/_/buckets/{bucket_id}"),
                file_path,
                bytes_data,
            )
            .send_buffered()
            .await?;

        Ok(())
    }
}

// TODO: Should probably be in a utils crate
#[derive(Debug)]
struct Tee<W1: Write, W2: Write> {
    writer1: W1,
    writer2: W2,
}

impl<W1: Write, W2: Write> Tee<W1, W2> {
    fn new(writer1: W1, writer2: W2) -> Self {
        Tee { writer1, writer2 }
    }
}

impl<W1: Write, W2: Write> Write for Tee<W1, W2> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer1.write_all(buf)?;
        self.writer2.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer1.flush()?;
        self.writer2.flush()?;
        Ok(())
    }
}
