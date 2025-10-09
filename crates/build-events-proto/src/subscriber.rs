//! gRPC streaming subscriber implementation
//!
//! Provides a [`GrpcStreamSubscriber`] that converts Rust events to protobuf
//! and makes them available as an async stream.

use async_trait::async_trait;
use build_events::{BuildEvent, BuildEventSubscriber, SubscriberError};
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tracing::warn;

use crate::proto;

/// Subscriber that converts events to protobuf and provides them as a stream
///
/// This subscriber implements [`BuildEventSubscriber`] and maintains an internal
/// broadcast channel for streaming events. It converts Rust events to protobuf
/// on reception and broadcasts them to all subscribers.
///
/// # Example
/// ```
/// use build_events_proto::GrpcStreamSubscriber;
///
/// // Create subscriber
/// let subscriber = GrpcStreamSubscriber::new(100);
///
/// // Can be used with BuildEventDispatcher
/// // dispatcher.add_subscriber(Box::new(subscriber));
/// ```
pub struct GrpcStreamSubscriber {
    sender: broadcast::Sender<proto::BuildEvent>,
}

impl GrpcStreamSubscriber {
    /// Create a new gRPC stream subscriber with the specified channel capacity
    ///
    /// The capacity determines how many events can be buffered before
    /// slow subscribers start lagging.
    ///
    /// # Arguments
    /// * `capacity` - Broadcast channel buffer capacity
    ///
    /// # Example
    /// ```
    /// use build_events_proto::GrpcStreamSubscriber;
    ///
    /// let subscriber = GrpcStreamSubscriber::new(100);
    /// ```
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribe to the event stream
    ///
    /// Returns a stream that receives all events broadcasted by this subscriber.
    /// Multiple subscriptions can be created, and each will receive all events.
    ///
    /// # Example
    /// ```
    /// use build_events_proto::GrpcStreamSubscriber;
    /// use tokio_stream::StreamExt;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let subscriber = GrpcStreamSubscriber::new(100);
    /// let mut stream = subscriber.subscribe_stream();
    ///
    /// // Consume events
    /// // while let Some(Ok(event)) = stream.next().await {
    /// //     // Process event
    /// // }
    /// # }
    /// ```
    pub fn subscribe_stream(&self) -> impl Stream<Item = proto::BuildEvent> {
        use tokio_stream::StreamExt;
        BroadcastStream::new(self.sender.subscribe()).filter_map(|result| result.ok())
    }

    /// Get a broadcast sender for this subscriber
    ///
    /// Useful for advanced use cases where you need direct access to the sender.
    pub fn sender(&self) -> broadcast::Sender<proto::BuildEvent> {
        self.sender.clone()
    }
}

#[async_trait]
impl BuildEventSubscriber for GrpcStreamSubscriber {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        // Extract invocation_id from the event (all variants have it)
        let invocation_id = match event {
            BuildEvent::BuildStarted(e) => &e.invocation_id,
            BuildEvent::BuildFinished(e) => &e.invocation_id,
            BuildEvent::TargetStarted(_) => "", // Targets don't have invocation_id in inner fields
            BuildEvent::TargetCompleted(_) => "",
            BuildEvent::ActionStarted(_) => "",
            BuildEvent::ActionCompleted(_) => "",
        };

        // Convert Rust event to proto using ergonomic extension trait
        use crate::convert::ToProto;
        let proto_event = event.to_proto(invocation_id);

        // Broadcast to all subscribers
        // If there are no subscribers, this is a no-op
        if self.sender.receiver_count() == 0 {
            return Ok(());
        }

        // Send to broadcast channel (will drop if no receivers)
        if let Err(e) = self.sender.send(proto_event) {
            // If channel has no receivers, this is expected
            warn!("GrpcStreamSubscriber: no active receivers ({})", e);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "GrpcStreamSubscriber"
    }

    async fn on_close(&self) -> Result<(), SubscriberError> {
        // Channel will automatically close when sender is dropped
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use build_events::events::{BuildStarted, current_millis};
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn test_subscriber_stream() {
        let subscriber = GrpcStreamSubscriber::new(10);
        let mut stream = subscriber.subscribe_stream();

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-123".to_string(),
            command: "test".to_string(),
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        // Send event
        subscriber.on_event(&event).await.unwrap();

        // Receive from stream
        let received = tokio::time::timeout(std::time::Duration::from_millis(100), stream.next())
            .await
            .unwrap();

        assert!(received.is_some());
        let proto_event = received.unwrap();
        assert!(proto_event.event.is_some());
    }

    #[tokio::test]
    async fn test_subscriber_name() {
        let subscriber = GrpcStreamSubscriber::new(10);
        assert_eq!(subscriber.name(), "GrpcStreamSubscriber");
    }
}
