//! SpongeBob gRPC client for streaming build events

use crate::proto::{
    build_event, BuildEvent, BuildStarted, FileCreated, OrderedBuildEvent, PublishBuildEventStreamRequest,
    build_event_service_client::BuildEventServiceClient,
};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

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
///
/// The client spawns a background task to continuously read from the
/// response stream, allowing non-blocking event publishing.
#[derive(Debug, Clone)]
pub struct SpongeBob {
    request_tx: Arc<Mutex<mpsc::Sender<PublishBuildEventStreamRequest>>>,
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
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let spongebob = build_events_proto::SpongeBob::new().await?;
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

        // Send initial BuildStarted event to initiate handshake
        // Server will respond with assigned invocation ID
        let timestamp_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        request_tx
            .send(PublishBuildEventStreamRequest {
                ordered_event: Some(OrderedBuildEvent {
                    sequence_number: 1,
                    stream_id: None, // Server will assign
                    event: Some(BuildEvent {
                        event: Some(build_event::Event::BuildStarted(BuildStarted {
                            command: std::env::args().collect::<Vec<_>>().join(" "),
                            timestamp_millis,
                            working_directory: std::env::current_dir()
                                .ok()
                                .and_then(|p| p.to_str().map(|s| s.to_string()))
                                .unwrap_or_default(),
                        })),
                    }),
                }),
            })
            .await
            .map_err(|e| SpongeBobError::Stream(format!("Failed to queue initial event: {}", e)))?;

        // Wrap receiver in a stream (initial BuildStarted is already queued)
        let request_stream = ReceiverStream::new(request_rx);

        // Open bidirectional stream - this will immediately have data to send
        let response = client.publish_build_event_stream(request_stream).await?;
        let mut response_stream = response.into_inner();

        // Create oneshot channel for first response
        let (first_response_tx, first_response_rx) = tokio::sync::oneshot::channel();

        // Spawn background task to continuously read responses
        // This task reads responses and sends the first one to the oneshot channel
        tokio::spawn(async move {
            let mut first_response_tx = Some(first_response_tx);

            loop {
                match response_stream.message().await {
                    Ok(Some(response)) => {
                        // Send first response to oneshot channel
                        if let Some(tx) = first_response_tx.take() {
                            let _ = tx.send(response);
                        } else {
                            // Log acknowledgment for debugging
                            tracing::debug!(
                                sequence_number = response.sequence_number,
                                "Received acknowledgment from server"
                            );
                        }
                    }
                    Ok(None) => {
                        // Stream closed by server
                        tracing::info!("Response stream closed by server");
                        break;
                    }
                    Err(e) => {
                        // Log error but don't crash - allow graceful degradation
                        tracing::warn!("Error reading from response stream: {}", e);
                        break;
                    }
                }
            }
        });

        // Wait for first response from background task
        let first_response = first_response_rx
            .await
            .map_err(|_| SpongeBobError::Stream("Background task died before first response".to_string()))?;

        let invocation_id = first_response
            .stream_id
            .ok_or_else(|| SpongeBobError::Stream("Server did not provide stream ID".to_string()))?
            .invocation_id;

        let url = format!("https://dash.minimal.farm/invocations/{}", invocation_id);

        tracing::info!(invocation_id = %invocation_id, "Received server-assigned invocation ID");

        Ok(Self {
            request_tx: Arc::new(Mutex::new(request_tx)),
            invocation_id,
            url,
            sequence_number: Arc::new(AtomicI64::new(2)), // Start at 2 (we used 1 for BuildStarted)
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
    ///
    /// This method is non-blocking - it sends the event to the stream without
    /// waiting for acknowledgment. Acknowledgments are processed asynchronously
    /// by a background task spawned in `new()`.
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

        tracing::debug!(sequence_number = seq, "Event sent to stream");

        Ok(())
    }

    /// Close the stream (drops the connection)
    ///
    /// If BuildFinished was not sent, the server will mark the invocation
    /// as terminated. The background task reading responses will detect
    /// the closed stream and terminate gracefully.
    pub async fn close(self) -> Result<()> {
        // Drop the request sender which will close the stream
        // The background task will detect the closed stream and terminate
        drop(self.request_tx);
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
