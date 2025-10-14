use minimal_spongebob_community_neoeinstein_prost::spongebob::v1::{
    build_event, BuildEvent, FileCreated, PublishBuildEventRequest,
};
use minimal_spongebob_community_neoeinstein_tonic::spongebob::v1::tonic::build_event_service_client::BuildEventServiceClient;
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
}

#[derive(Debug, Clone)]
pub struct SpongeBobInvocation {
    build_event_service: BuildEventServiceClient<Channel>,
    invocation_id: String,
    url: String,
}

impl SpongeBobInvocation {
    /// Create a new invocation (no RPC needed - invocation created on first BuildStarted event)
    pub fn new(
        build_event_service: BuildEventServiceClient<Channel>,
        invocation_id: String,
    ) -> Self {
        let url = format!(
            "{}/invocations/{}",
            "https://dash.minimal.dev", invocation_id
        );
        Self {
            build_event_service,
            invocation_id,
            url,
        }
    }

    /// Publish a FileCreated event to upload a file for a specific target
    #[tracing::instrument(skip(self, contents))]
    pub async fn publish_file_created_event(
        &mut self,
        target_id: &str,
        file_name: &str,
        contents: Vec<u8>,
    ) -> Result<()> {
        let timestamp_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let file_created = FileCreated {
            target_id: target_id.to_string(),
            name: file_name.to_string(),
            contents: contents.into(),
            timestamp_millis,
        };

        let event = BuildEvent {
            invocation_id: self.invocation_id.clone(),
            event: Some(build_event::Event::FileCreated(file_created)),
        };

        self.publish_build_event(event).await?;
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

        Ok(SpongeBob {
            build_event_service,
        })
    }

    /// Create a new invocation handle (no RPC - invocation created on first BuildStarted event)
    pub fn create_invocation(&mut self) -> SpongeBobInvocation {
        let invocation_id = Uuid::new_v4().to_string();
        SpongeBobInvocation::new(
            self.build_event_service.clone(),
            invocation_id,
        )
    }
}
