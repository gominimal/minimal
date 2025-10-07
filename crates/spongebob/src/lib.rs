use minimal_spongebob_community_neoeinstein_prost::spongebob::v1::{CreateFileRequest, CreateInvocationRequest, File, Invocation};
use minimal_spongebob_community_neoeinstein_tonic::spongebob::v1::tonic::sponge_bob_service_client::SpongeBobServiceClient;
use tonic::transport::Channel;
use uuid::Uuid;

const ENDPOINT: &str = "https://spongebob.minimal.farm";

#[derive(thiserror::Error, Debug)]
pub enum SpongeBobError {
    #[error("Failed to connect to SpongeBob service: {0}")]
    Connection(#[from] tonic::transport::Error),
    #[error("SpongeBob service error: {0}")]
    Service(#[from] tonic::Status),
}

pub type Result<T> = std::result::Result<T, SpongeBobError>;

#[derive(Debug)]
pub struct SpongeBob {
    service: SpongeBobServiceClient<Channel>,
}

#[derive(Debug, Clone)]
pub struct SpongeBobInvocation {
    service: SpongeBobServiceClient<Channel>,
    resource_name: String,
    url: String,
}

impl SpongeBobInvocation {
    #[tracing::instrument(skip(self, contents))]
    pub async fn upload_file(&mut self, file_name: &str, contents: Vec<u8>) -> Result<()> {
        let file_id = Uuid::new_v4().to_string();
        let request = CreateFileRequest {
            parent: self.resource_name.clone(),
            file_id,
            file: Some(File {
                name: file_name.to_string(),
                contents: contents.into(),
            }),
        };

        self.service.create_file(request).await?;
        Ok(())
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn resource_name(&self) -> &str {
        &self.resource_name
    }
}

impl SpongeBob {
    pub async fn new() -> Result<Self> {
        let service = SpongeBobServiceClient::connect(ENDPOINT).await?;

        Ok(SpongeBob { service })
    }

    #[tracing::instrument]
    pub async fn create_invocation(&mut self, name: &str) -> Result<SpongeBobInvocation> {
        let invocation_id = Self::generate_invocation_id(name);
        let resource_name = self.create_invocation_with_id(name, &invocation_id).await?;
        let url = self.generate_invocation_url(&invocation_id);

        Ok(SpongeBobInvocation {
            service: self.service.clone(),
            resource_name,
            url,
        })
    }

    #[tracing::instrument]
    async fn create_invocation_with_id(
        &mut self,
        name: &str,
        invocation_id: &str,
    ) -> Result<String> {
        let request = CreateInvocationRequest {
            invocation_id: invocation_id.to_string(),
            invocation: Some(Invocation {
                name: name.to_string(),
            }),
        };

        let response = self.service.create_invocation(request).await?;
        Ok(response.into_inner().name)
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
