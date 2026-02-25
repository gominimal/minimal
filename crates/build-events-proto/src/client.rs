//! SpongeBob gRPC client for streaming build events

use crate::proto::{BuildEvent, build_event_service_client::BuildEventServiceClient};
use async_trait::async_trait;
use build_events::{BuildEventSubscriber, SubscriberError};
use std::sync::Arc;
use tokio::sync::mpsc;
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

/// SpongeBob client for streaming build events
///
/// Creates a client streaming connection for publishing build events.
/// All events are published through this stream.
/// The server sends an Empty response when the stream closes.
#[derive(Debug)]
pub struct SpongeBob {
    request_tx: Arc<tokio::sync::Mutex<Option<mpsc::Sender<BuildEvent>>>>,
    stream_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl Clone for SpongeBob {
    fn clone(&self) -> Self {
        Self {
            request_tx: self.request_tx.clone(),
            stream_handle: self.stream_handle.clone(),
        }
    }
}

impl SpongeBob {
    /// Create a new SpongeBob client and open streaming connection
    ///
    /// This immediately connects to the server and opens a client
    /// streaming connection. The provided invocation ID is logged for tracking.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let invocation_id = uuid::Uuid::new_v4().to_string();
    /// let spongebob = build_events_proto::SpongeBob::new(invocation_id).await?;
    /// // Invocation URL is automatically logged
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument]
    pub async fn new(invocation_id: String) -> Result<Self> {
        // Connect to service
        let mut client = BuildEventServiceClient::connect(ENDPOINT).await?;

        // Create channel for client streaming
        let (request_tx, request_rx) = mpsc::channel(100);

        // Log invocation URL at start
        tracing::info!("https://dash.minimal.farm/invocations/{}", invocation_id);

        // Spawn task to handle stream and wait for response
        let invocation_id_for_task = invocation_id.clone();
        let stream_handle = tokio::spawn(async move {
            let request_stream = ReceiverStream::new(request_rx);
            match client.publish_build_event_stream(request_stream).await {
                Ok(_response) => {
                    tracing::info!("Stream closed successfully");
                    tracing::info!(
                        "https://dash.minimal.farm/invocations/{}",
                        invocation_id_for_task
                    );
                }
                Err(e) => {
                    tracing::error!("Stream error: {}", e);
                    tracing::info!(
                        "https://dash.minimal.farm/invocations/{}",
                        invocation_id_for_task
                    );
                }
            }
        });

        Ok(Self {
            request_tx: Arc::new(tokio::sync::Mutex::new(Some(request_tx))),
            stream_handle: Arc::new(tokio::sync::Mutex::new(Some(stream_handle))),
        })
    }

    /// Publish a build event to Spongebob via the streaming connection
    ///
    /// This method is non-blocking - it sends the event to the channel.
    /// The background task handles sending to the server.
    #[tracing::instrument(skip(self, event))]
    pub async fn publish_build_event(&self, event: BuildEvent) -> Result<()> {
        let tx_lock = self.request_tx.lock().await;
        if let Some(tx) = tx_lock.as_ref() {
            tx.send(event)
                .await
                .map_err(|e| SpongeBobError::Stream(format!("Failed to send event: {}", e)))?;

            tracing::debug!("Event queued for sending");
            Ok(())
        } else {
            Err(SpongeBobError::Stream("Stream already closed".to_string()))
        }
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
        tracing::debug!("Closing SpongeBob client and waiting for stream to complete");

        // Drop the request sender to close the stream
        {
            let mut tx_lock = self.request_tx.lock().await;
            tx_lock.take(); // This drops the sender, closing the channel
        }

        // Wait for the stream handler task to complete and log the final URL
        let mut handle_lock = self.stream_handle.lock().await;
        if let Some(handle) = handle_lock.take() {
            if let Err(e) = handle.await {
                tracing::warn!("Stream handler task failed: {}", e);
            }
        }

        Ok(())
    }
}
