use anyhow::{Result, bail};
use bytes::Bytes;
use google_cloud_gax::error::rpc::Code;
use google_cloud_storage::client::{Storage, StorageControl};
use sha2::{Digest, Sha256};

use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RemoteStorage {
    client: Storage,
    cache_dir: PathBuf,
    control_client: StorageControl,
}

impl RemoteStorage {
    pub async fn new() -> Result<Self> {
        let cache_dir = {
            let dir = dirs::cache_dir().unwrap().join("minimal-fetches");
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
        let control_client = StorageControl::builder().build().await?;
        Ok(Self {
            client,
            cache_dir,
            control_client,
        })
    }

    pub async fn download_with_verification_and_caching(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
    ) -> Result<Bytes> {
        if sha256.contains("/") {
            bail!("SHA256 had a slash in it");
        }

        let download_path = self.cache_dir.join(sha256);

        if fs::exists(&download_path)? {
            let file_contents = fs::read(&download_path)?;
            // Verify SHA256 hash
            let mut hasher = Sha256::new();
            hasher.update(&file_contents);
            let computed_hash = hasher.finalize();
            let computed_hex = hex::encode(computed_hash);

            if computed_hex == sha256 {
                return Ok(file_contents.into());
            }
        }

        let data = self.download(bucket_id.clone(), file).await?;
        {
            let mut f = fs::File::create(download_path)?;
            f.write(&data).unwrap();
            f.sync_data()?;
        }

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let computed_hash = hasher.finalize();
        let computed_hex = hex::encode(computed_hash);

        if computed_hex != sha256 {
            bail!(
                "SHA256 mismatch for {}//{}: expected {}, got {}",
                bucket_id,
                file,
                sha256,
                computed_hex
            );
        }
        Ok(data)
    }

    pub async fn download(&self, bucket_id: String, file: &str) -> Result<Bytes> {
        eprintln!("Fetching {} from bucket {}", file, bucket_id);
        let mut reader = self
            .client
            .read_object(format!("projects/_/buckets/{bucket_id}"), file)
            .send()
            .await?;
        let mut contents = Vec::new();
        while let Some(chunk) = reader.next().await.transpose()? {
            contents.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(contents))
    }

    pub async fn upload(&self, bucket_id: &str, file_path: &str, data: &[u8]) -> Result<()> {
        eprintln!("Uploading {} to bucket {}", file_path, bucket_id);

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

        println!(
            "Successfully uploaded {} bytes to gs://{}/{}",
            data.len(),
            bucket_id,
            file_path
        );

        Ok(())
    }

    pub async fn exists(&self, bucket_id: &str, file_path: &str) -> Result<bool> {
        match self
            .control_client
            .get_object()
            .set_bucket(format!("projects/_/buckets/{bucket_id}"))
            .set_object(file_path)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if let Some(status) = e.status()
                    && status.code == Code::NotFound
                {
                    return Ok(false);
                }
                Err(e.into())
            }
        }
    }
}
