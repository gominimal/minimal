//! gRPC service implementation for build events
//!
//! Provides a [`BuildEventServiceImpl`] that implements the gRPC service
//! defined in the protobuf schema.

use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tracing::{info, warn};

use crate::proto;
use crate::proto::build_event_service_server::BuildEventService;

/// Implementation of the BuildEventService gRPC service
///
/// This service provides server-side streaming of build events. It uses
/// a broadcast channel to allow multiple clients to subscribe to the same
/// event stream concurrently.
///
/// # Example
/// ```no_run
/// use build_events_proto::{BuildEventServiceImpl, proto::build_event_service_server::BuildEventServiceServer};
/// use tonic::transport::Server;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let service = BuildEventServiceImpl::new(1000);
///
///     Server::builder()
///         .add_service(BuildEventServiceServer::new(service))
///         .serve("[::1]:50051".parse()?)
///         .await?;
///
///     Ok(())
/// }
/// ```
pub struct BuildEventServiceImpl {
    event_sender: broadcast::Sender<proto::BuildEvent>,
}

impl BuildEventServiceImpl {
    /// Create a new build event service with the specified channel capacity
    ///
    /// # Arguments
    /// * `capacity` - Broadcast channel capacity
    ///
    /// # Example
    /// ```
    /// use build_events_proto::BuildEventServiceImpl;
    ///
    /// let service = BuildEventServiceImpl::new(1000);
    /// ```
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            event_sender: sender,
        }
    }

    /// Publish an event to all subscribers
    ///
    /// This method allows the build system to publish events that will
    /// be streamed to all connected gRPC clients.
    ///
    /// # Arguments
    /// * `event` - The protobuf event to publish
    ///
    /// # Example
    /// ```
    /// use build_events_proto::{BuildEventServiceImpl, proto};
    ///
    /// let service = BuildEventServiceImpl::new(1000);
    /// let event = proto::BuildEvent {
    ///     invocation_id: String::new(),
    ///     event: None
    /// };
    /// service.publish(event);
    /// ```
    pub fn publish(&self, event: proto::BuildEvent) {
        // Broadcast to all subscribers
        // If there are no subscribers, this is a no-op
        let subscriber_count = self.event_sender.receiver_count();
        if subscriber_count == 0 {
            return;
        }

        if let Err(e) = self.event_sender.send(event) {
            warn!("Failed to broadcast event: no receivers ({})", e);
        }
    }

    /// Get a sender for publishing events
    ///
    /// This is useful for integrating with the build system's event bus.
    pub fn sender(&self) -> broadcast::Sender<proto::BuildEvent> {
        self.event_sender.clone()
    }

    /// Get the current number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.event_sender.receiver_count()
    }
}

#[tonic::async_trait]
impl BuildEventService for BuildEventServiceImpl {
    type StreamBuildEventsStream = std::pin::Pin<
        Box<dyn Stream<Item = Result<proto::BuildEvent, tonic::Status>> + Send + 'static>,
    >;

    async fn stream_build_events(
        &self,
        request: tonic::Request<proto::StreamBuildEventsRequest>,
    ) -> Result<tonic::Response<Self::StreamBuildEventsStream>, tonic::Status> {
        let req = request.into_inner();

        info!(
            "New event stream subscription: invocation_id={:?}, start_timestamp={:?}",
            req.invocation_id, req.start_timestamp_millis
        );

        // Subscribe to the broadcast channel
        let receiver = self.event_sender.subscribe();
        let stream = BroadcastStream::new(receiver);

        // Apply filters if specified
        let invocation_filter = req.invocation_id.clone();
        let timestamp_filter = req.start_timestamp_millis;

        // Wrap the stream with filtering logic and error mapping
        let filtered_stream = stream.filter_map(move |result| {
            match result {
                Ok(event) => {
                    // Note: invocation_id filtering is no longer supported at event level
                    // since events are implicitly associated with invocations via the stream
                    if invocation_filter.is_some() {
                        // Ignore filter for now - would need to track at stream level
                    }

                    // Apply timestamp filter if specified
                    if let Some(start_ts) = timestamp_filter {
                        let event_ts = match &event.event {
                            Some(proto::build_event::Event::BuildStarted(e)) => e.timestamp_millis,
                            Some(proto::build_event::Event::BuildFinished(e)) => e.timestamp_millis,
                            Some(proto::build_event::Event::TargetStarted(e)) => e.timestamp_millis,
                            Some(proto::build_event::Event::TargetCompleted(e)) => {
                                e.timestamp_millis
                            }
                            Some(proto::build_event::Event::ActionStarted(e)) => e.timestamp_millis,
                            Some(proto::build_event::Event::ActionCompleted(e)) => {
                                e.timestamp_millis
                            }
                            Some(proto::build_event::Event::BuildMetadata(_)) => 0, // Metadata events have no timestamp
                            Some(proto::build_event::Event::FileCreated(e)) => e.timestamp_millis,
                            None => return None,
                        };

                        if event_ts < start_ts {
                            return None;
                        }
                    }

                    Some(Ok(event))
                }
                Err(e) => {
                    warn!("Broadcast stream error: {}", e);
                    // Convert to gRPC status
                    Some(Err(tonic::Status::internal(format!("Stream error: {}", e))))
                }
            }
        });

        Ok(tonic::Response::new(Box::pin(filtered_stream)))
    }

    async fn publish_build_event(
        &self,
        request: tonic::Request<proto::PublishBuildEventRequest>,
    ) -> Result<tonic::Response<proto::PublishBuildEventResponse>, tonic::Status> {
        let req = request.into_inner();

        // Extract the event from the request
        let event = req
            .event
            .ok_or_else(|| tonic::Status::invalid_argument("Missing event in request"))?;

        // Publish to broadcast channel
        self.publish(event);

        // Return success response with empty name (will be set by server)
        Ok(tonic::Response::new(proto::PublishBuildEventResponse {
            name: String::new(),
        }))
    }

    type PublishBuildEventStreamStream = std::pin::Pin<
        Box<dyn Stream<Item = Result<proto::PublishBuildEventStreamResponse, tonic::Status>> + Send + 'static>,
    >;

    async fn publish_build_event_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<proto::PublishBuildEventStreamRequest>>,
    ) -> Result<tonic::Response<Self::PublishBuildEventStreamStream>, tonic::Status> {
        // Not implemented in this service - this is a client-side method
        Err(tonic::Status::unimplemented(
            "Bidirectional streaming not implemented in this build events service"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        let service = BuildEventServiceImpl::new(100);
        assert_eq!(service.subscriber_count(), 0);
    }

    #[test]
    fn test_publish_no_subscribers() {
        let service = BuildEventServiceImpl::new(100);
        let event = proto::BuildEvent {
            invocation_id: String::new(),
            event: None,
        };
        // Should not panic
        service.publish(event);
    }

    #[tokio::test]
    async fn test_subscriber_count() {
        let service = BuildEventServiceImpl::new(100);
        assert_eq!(service.subscriber_count(), 0);

        let _rx1 = service.event_sender.subscribe();
        assert_eq!(service.subscriber_count(), 1);

        let _rx2 = service.event_sender.subscribe();
        assert_eq!(service.subscriber_count(), 2);
    }
}
