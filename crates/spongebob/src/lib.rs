use std::time::{SystemTime, UNIX_EPOCH};
use tonic::transport::{Channel, ClientTlsConfig};
use uuid::Uuid;

use crate::api::{
    CreateFileRequest, CreateInvokationRequest, File, Invokation,
    sponge_bob_service_client::SpongeBobServiceClient,
};

pub mod api {
    tonic::include_proto!("spongebob.v1");
}

const ENDPOINT: &str = "https://spongebob-289724348228.us-west1.run.app";

#[derive(thiserror::Error, Debug)]
pub enum SpongeBobError {
    #[error("Failed to connect to SpongeBob service: {0}")]
    Connection(#[from] tonic::transport::Error),
    #[error("SpongeBob service error: {0}")]
    Service(#[from] tonic::Status),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SpongeBobError>;

#[derive(Debug)]
pub struct SpongeBob {
    service: SpongeBobServiceClient<Channel>,
}

impl SpongeBob {
    pub async fn new() -> Result<Self> {
        let tls_config = ClientTlsConfig::new().with_native_roots();
        let channel = Channel::from_static(ENDPOINT)
            .tls_config(tls_config)
            .unwrap()
            .connect()
            .await?;
        let service = SpongeBobServiceClient::new(channel);

        Ok(SpongeBob { service })
    }

    pub async fn with_endpoint(endpoint: &'static str) -> Result<Self> {
        let channel = Channel::from_static(endpoint).connect().await?;
        let service = SpongeBobServiceClient::new(channel);

        Ok(SpongeBob { service })
    }

    pub async fn create_invokation(&mut self, name: &str) -> Result<String> {
        let invokation_id = Self::generate_invokation_id(name);
        let request = CreateInvokationRequest {
            invokation_id: invokation_id.clone(),
            invokation: Some(Invokation {
                name: name.to_string(),
            }),
        };

        let response = self.service.create_invokation(request).await?;
        Ok(response.into_inner().name)
    }

    pub async fn create_file(
        &mut self,
        parent_invokation_resource: &str,
        file_name: &str,
        contents: Vec<u8>,
    ) -> Result<()> {
        let file_id = Uuid::new_v4().to_string();
        let request = CreateFileRequest {
            parent: parent_invokation_resource.to_string(),
            file_id,
            file: Some(File {
                name: file_name.to_string(),
                contents,
            }),
        };

        self.service.create_file(request).await?;
        Ok(())
    }

    pub async fn upload_build_logs(
        &mut self,
        build_name: &str,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<()> {
        // Create invokation for this build
        let invokation_resource = self.create_invokation(build_name).await?;

        // Upload stdout
        self.create_file(&invokation_resource, "stdout", stdout)
            .await?;

        // Upload stderr
        self.create_file(&invokation_resource, "stderr", stderr)
            .await?;

        Ok(())
    }

    fn generate_invokation_id(name: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        format!("{}-{}-{}", name, timestamp, Uuid::new_v4())
    }
}
