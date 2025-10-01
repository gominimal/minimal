use tonic::transport::{Channel, ClientTlsConfig};
use uuid::Uuid;

use crate::api::{
    CreateFileRequest, CreateInvocationRequest, File, Invocation,
    sponge_bob_service_client::SpongeBobServiceClient,
};

pub mod api {
    tonic::include_proto!("spongebob.v1");
}

const ENDPOINT: &str = "https://spongebob.minimal.farm";

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

    pub async fn create_invocation(&mut self, name: &str) -> Result<String> {
        let invocation_id = Self::generate_invocation_id(name);
        self.create_invocation_with_id(name, &invocation_id).await
    }

    pub async fn create_invocation_with_url(&mut self, name: &str) -> Result<(String, String)> {
        let invocation_id = Self::generate_invocation_id(name);
        let resource_name = self.create_invocation_with_id(name, &invocation_id).await?;
        let url = self.generate_invocation_url(&invocation_id);
        Ok((resource_name, url))
    }

    async fn create_invocation_with_id(&mut self, name: &str, invocation_id: &str) -> Result<String> {
        let request = CreateInvocationRequest {
            invocation_id: invocation_id.to_string(),
            invocation: Some(Invocation {
                name: name.to_string(),
            }),
        };

        let response = self.service.create_invocation(request).await?;
        Ok(response.into_inner().name)
    }

    pub async fn create_file(
        &mut self,
        parent_invocation_resource: &str,
        file_name: &str,
        contents: Vec<u8>,
    ) -> Result<()> {
        let file_id = Uuid::new_v4().to_string();
        let request = CreateFileRequest {
            parent: parent_invocation_resource.to_string(),
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
    ) -> Result<String> {
        // Generate invocation ID first
        let invocation_id = Self::generate_invocation_id(build_name);

        // Create invocation for this build
        let invocation_resource = self.create_invocation_with_id(build_name, &invocation_id).await?;

        // Upload stdout
        self.create_file(&invocation_resource, "stdout", stdout)
            .await?;

        // Upload stderr
        self.create_file(&invocation_resource, "stderr", stderr)
            .await?;

        // Generate and return the viewable URL
        let spongebob_url = self.generate_invocation_url(&invocation_id);

        Ok(spongebob_url)
    }

    fn generate_invocation_id(_name: &str) -> String {
        // Just use a UUID for the invocation ID to ensure URL safety
        Uuid::new_v4().to_string()
    }

    /// Generate the web URL for viewing an invocation
    fn generate_invocation_url(&self, invocation_id: &str) -> String {
        format!("{}/invocation/{}", ENDPOINT, invocation_id)
    }
}
