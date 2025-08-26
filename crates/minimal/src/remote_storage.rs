use anyhow::Result;
use bytes::Bytes;
use google_cloud_storage::client::Storage;

pub struct RemoteStorage {
    client: Storage,
}

impl RemoteStorage {
    pub async fn new() -> Result<Self> {
        // Use Application Default Credentials with proper scopes
        let client = Storage::builder().build().await?;
        Ok(Self { client })
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

    pub async fn upload(&self, bucket_id: String, file_path: &str, data: &[u8]) -> Result<()> {
        eprintln!("Uploading {} to bucket {}", file_path, bucket_id);
        
        // Upload object using the correct GCS API
        let bytes_data = bytes::Bytes::copy_from_slice(data);
        let _response = self.client
            .upload_object(
                format!("projects/_/buckets/{bucket_id}"), 
                file_path, 
                bytes_data
            )
            .send_buffered()
            .await?;
        
        println!("Successfully uploaded {} bytes to gs://{}/{}", data.len(), bucket_id, file_path);
        
        Ok(())
    }
}
