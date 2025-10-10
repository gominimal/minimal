use minimal_spongebob_community_neoeinstein_prost::spongebob::v1::{
    BuildEvent, CreateFileRequest, File, PublishBuildEventRequest,
};
use minimal_spongebob_community_neoeinstein_tonic::spongebob::v1::tonic::{
    build_event_service_client::BuildEventServiceClient,
    result_storage_service_client::ResultStorageServiceClient,
};
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
    build_event_service: BuildEventServiceClient<Channel>,
    result_storage_service: ResultStorageServiceClient<Channel>,
}

#[derive(Debug, Clone)]
pub struct SpongeBobInvocation {
    build_event_service: BuildEventServiceClient<Channel>,
    result_storage_service: ResultStorageServiceClient<Channel>,
    invocation_id: String,
    url: String,
}

impl SpongeBobInvocation {
    /// Create a new invocation (no RPC needed - invocation created on first BuildStarted event)
    pub fn new(
        build_event_service: BuildEventServiceClient<Channel>,
        result_storage_service: ResultStorageServiceClient<Channel>,
        invocation_id: String,
    ) -> Self {
        let url = format!(
            "{}/invocations/{}",
            "https://dash.minimal.dev", invocation_id
        );
        Self {
            build_event_service,
            result_storage_service,
            invocation_id,
            url,
        }
    }

    /// Upload a file to a specific target within this invocation
    #[tracing::instrument(skip(self, contents))]
    pub async fn upload_file(
        &mut self,
        target_id: &str,
        file_name: &str,
        contents: Vec<u8>,
    ) -> Result<()> {
        let parent = format!("invocations/{}/targets/{}", self.invocation_id, target_id);
        let request = CreateFileRequest {
            parent,
            file_id: file_name.to_string(),
            file: Some(File {
                name: file_name.to_string(),
                contents: contents.into(),
            }),
        };

        self.result_storage_service.create_file(request).await?;
        Ok(())
    }

    /// Publish a build event to Spongebob
    /// Invocation is auto-created on first BuildStarted event
    #[tracing::instrument(skip(self, event))]
    pub async fn publish_build_event(&mut self, event: BuildEvent) -> Result<()> {
        let request = PublishBuildEventRequest {
            event: Some(event),
            request_id: String::new(), // Optional idempotency key
        };

        self.build_event_service
            .publish_build_event(request)
            .await?;
        Ok(())
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn resource_name(&self) -> String {
        format!("invocations/{}", self.invocation_id)
    }
}

impl SpongeBob {
    pub async fn new() -> Result<Self> {
        let build_event_service = BuildEventServiceClient::connect(ENDPOINT).await?;
        let result_storage_service = ResultStorageServiceClient::connect(ENDPOINT).await?;

        Ok(SpongeBob {
            build_event_service,
            result_storage_service,
        })
    }

    /// Create a new invocation handle (no RPC - invocation created on first BuildStarted event)
    pub fn create_invocation(&mut self) -> SpongeBobInvocation {
        let invocation_id = Uuid::new_v4().to_string();
        SpongeBobInvocation::new(
            self.build_event_service.clone(),
            self.result_storage_service.clone(),
            invocation_id,
        )
    }
}
