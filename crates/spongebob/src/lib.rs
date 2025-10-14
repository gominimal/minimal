use minimal_spongebob_community_neoeinstein_prost::spongebob::v1::{
    build_event, BuildEvent, FileCreated, OrderedBuildEvent, PublishBuildEventStreamRequest,
    PublishBuildEventStreamResponse,
};
use minimal_spongebob_community_neoeinstein_tonic::spongebob::v1::tonic::build_event_service_client::BuildEventServiceClient;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

const ENDPOINT: &str = "https://spongebob.minimal.farm";

#[derive(thiserror::Error, Debug)]
pub enum SpongeBobError {
    #[error("Failed to connect to SpongeBob service: {0}")]
    Connection(#[from] tonic::transport::Error),
    #[error("SpongeBob service error: {0}")]
    Service(#[from] tonic::Status),
    #[error("Stream error: {0}")]
    Stream(String),
}

pub type Result<T> = std::result::Result<T, SpongeBobError>;

/// SpongeBob client with server-assigned invocation ID
///
/// Creates a bidirectional stream on initialization and receives
/// a server-assigned invocation ID. All events are published through
/// this stream with monotonically increasing sequence numbers.
#[derive(Debug, Clone)]
pub struct SpongeBob {
    request_tx: Arc<Mutex<mpsc::Sender<PublishBuildEventStreamRequest>>>,
    response_stream: Arc<Mutex<Streaming<PublishBuildEventStreamResponse>>>,
    invocation_id: String,
    url: String,
    sequence_number: Arc<AtomicI64>,
}

impl SpongeBob {
    /// Create a new SpongeBob client and open streaming connection
    ///
    /// This immediately connects to the server and opens a bidirectional
    /// stream. The server assigns an invocation ID which is returned in
    /// the first response.
    ///
    /// # Example
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let spongebob = spongebob::SpongeBob::new().await?;
    /// println!("Invocation URL: {}", spongebob.url());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument]
    pub async fn new() -> Result<Self> {
        // Connect to service
        let mut client = BuildEventServiceClient::connect(ENDPOINT).await?;

        // Create channel for bidirectional streaming
        let (request_tx, request_rx) = mpsc::channel(100);

        // Wrap receiver in a stream
        let request_stream = ReceiverStream::new(request_rx);

        // Open bidirectional stream
        let response = client.publish_build_event_stream(request_stream).await?;
        let mut response_stream = response.into_inner();

        // Send first request with sequence number 1 to get server-assigned ID
        request_tx
            .send(PublishBuildEventStreamRequest {
                ordered_event: Some(OrderedBuildEvent {
                    sequence_number: 1,
                    stream_id: None,
                    event: None,
                }),
            })
            .await
            .map_err(|e| SpongeBobError::Stream(format!("Failed to send initial request: {}", e)))?;

        // Wait for first response with server-assigned invocation ID
        let first_response = response_stream
            .message()
            .await?
            .ok_or_else(|| SpongeBobError::Stream("No response from server".to_string()))?;

        let invocation_id = first_response
            .stream_id
            .ok_or_else(|| SpongeBobError::Stream("Server did not provide stream ID".to_string()))?
            .invocation_id;

        let url = format!("https://dash.minimal.dev/invocations/{}", invocation_id);

        tracing::info!(invocation_id = %invocation_id, "Received server-assigned invocation ID");

        Ok(Self {
            request_tx: Arc::new(Mutex::new(request_tx)),
            response_stream: Arc::new(Mutex::new(response_stream)),
            invocation_id,
            url,
            sequence_number: Arc::new(AtomicI64::new(2)), // Start at 2 (we used 1 for initial request)
        })
    }

    /// Publish a FileCreated event to upload a file for a specific target
    #[tracing::instrument(skip(self, contents))]
    pub async fn publish_file_created_event(
        &self,
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
            event: Some(build_event::Event::FileCreated(file_created)),
        };

        self.publish_build_event(event).await
    }

    /// Publish a build event to Spongebob via the streaming connection
    #[tracing::instrument(skip(self, event))]
    pub async fn publish_build_event(&self, event: BuildEvent) -> Result<()> {
        let seq = self.sequence_number.fetch_add(1, Ordering::SeqCst);

        // Send event with sequence number
        let request = PublishBuildEventStreamRequest {
            ordered_event: Some(OrderedBuildEvent {
                sequence_number: seq,
                stream_id: None, // Only needed on first message
                event: Some(event),
            }),
        };

        let request_tx = self.request_tx.lock().await;
        request_tx
            .send(request)
            .await
            .map_err(|e| SpongeBobError::Stream(format!("Failed to send event: {}", e)))?;

        // Wait for acknowledgment
        let mut response_stream = self.response_stream.lock().await;
        let _ack = response_stream
            .message()
            .await?
            .ok_or_else(|| SpongeBobError::Stream("No acknowledgment from server".to_string()))?;

        tracing::debug!(sequence_number = seq, "Event acknowledged by server");

        Ok(())
    }

    /// Close the stream (drops the connection)
    ///
    /// If BuildFinished was not sent, the server will mark the invocation
    /// as terminated.
    pub async fn close(self) -> Result<()> {
        // Drop the request sender which will close the stream
        drop(self.request_tx);
        drop(self.response_stream);
        Ok(())
    }

    /// Get the server-assigned invocation ID
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    /// Get the dashboard URL for this invocation
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the resource name for this invocation
    pub fn resource_name(&self) -> String {
        format!("invocations/{}", self.invocation_id)
    }
}
