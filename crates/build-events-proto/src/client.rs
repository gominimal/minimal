//! SpongeBob gRPC client for streaming build events

use crate::proto::{
    build_event, BuildEvent, BuildStarted, build_event_service_client::BuildEventServiceClient,
};
use async_trait::async_trait;
use build_events::{BuildEventSubscriber, SubscriberError};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

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

/// SpongeBob client with client-generated invocation ID
///
/// Creates a client streaming connection with a client-generated
/// invocation ID. All events are published through this stream.
/// The server sends an Empty response when the stream closes.
#[derive(Debug, Clone)]
pub struct SpongeBob {
    request_tx: mpsc::Sender<BuildEvent>,
    invocation_id: Arc<String>,
}

impl SpongeBob {
    /// Create a new SpongeBob client and open streaming connection
    ///
    /// This immediately connects to the server and opens a client
    /// streaming connection. The client generates an invocation ID which is logged.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let spongebob = build_events_proto::SpongeBob::new().await?;
    /// // Invocation URL is automatically logged
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument]
    pub async fn new() -> Result<Self> {
        // Generate invocation ID on client side
        let invocation_id = Uuid::new_v4().to_string();

        // Connect to service
        let mut client = BuildEventServiceClient::connect(ENDPOINT).await?;

        // Create channel for client streaming
        let (request_tx, request_rx) = mpsc::channel(100);

        // Send initial BuildStarted event with client-generated invocation ID
        let timestamp_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        request_tx
            .send(BuildEvent {
                event: Some(build_event::Event::BuildStarted(BuildStarted {
                    invocation_id: invocation_id.clone(),
                    command: std::env::args().collect::<Vec<_>>().join(" "),
                    timestamp_millis,
                    working_directory: std::env::current_dir()
                        .ok()
                        .and_then(|p| p.to_str().map(|s| s.to_string()))
                        .unwrap_or_default(),
                })),
            })
            .await
            .map_err(|e| SpongeBobError::Stream(format!("Failed to queue initial event: {}", e)))?;

        // Log invocation URL at start
        tracing::info!("https://dash.minimal.farm/invocations/{}", invocation_id);

        // Spawn task to handle stream and wait for response
        let invocation_id_for_task = invocation_id.clone();
        tokio::spawn(async move {
            let request_stream = ReceiverStream::new(request_rx);
            match client.publish_build_event_stream(request_stream).await {
                Ok(_response) => {
                    tracing::info!("Stream closed successfully");
                    tracing::info!("https://dash.minimal.farm/invocations/{}", invocation_id_for_task);
                }
                Err(e) => {
                    tracing::error!("Stream error: {}", e);
                    tracing::info!("https://dash.minimal.farm/invocations/{}", invocation_id_for_task);
                }
            }
        });

        Ok(Self {
            request_tx,
            invocation_id: Arc::new(invocation_id),
        })
    }

    /// Publish a build event to Spongebob via the streaming connection
    ///
    /// This method is non-blocking - it sends the event to the channel.
    /// The background task handles sending to the server.
    #[tracing::instrument(skip(self, event))]
    pub async fn publish_build_event(&self, event: BuildEvent) -> Result<()> {
        self.request_tx
            .send(event)
            .await
            .map_err(|e| SpongeBobError::Stream(format!("Failed to send event: {}", e)))?;

        tracing::debug!("Event queued for sending");

        Ok(())
    }

    /// Close the stream and wait for final response
    ///
    /// Drops the request sender which closes the stream. The server will
    /// process all events and send a final response. The background task
    /// will log the final status.
    pub async fn close(self) -> Result<()> {
        // Drop the request sender which closes the stream
        drop(self.request_tx);
        // Background task will receive the final response and log it
        Ok(())
    }
}

/// Implement BuildEventSubscriber trait to allow SpongeBob client to be used
/// directly as a subscriber in the build events dispatcher.
#[async_trait]
impl BuildEventSubscriber for SpongeBob {
    async fn on_event(&self, event: &BuildEvent) -> std::result::Result<(), SubscriberError> {
        // Publish all events to SpongeBob
        match self.publish_build_event(event.clone()).await {
            Ok(()) => {
                tracing::debug!("Successfully published build event to Spongebob");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Failed to publish build event to Spongebob: {}", e);
                Err(SubscriberError::Custom(format!(
                    "Failed to publish event: {}",
                    e
                )))
            }
        }
    }

    fn name(&self) -> &str {
        "SpongeBob"
    }

    async fn on_close(&self) -> std::result::Result<(), SubscriberError> {
        // No cleanup needed - connection will be closed when dropped
        Ok(())
    }
}
