//! Build event subscriber trait and error types
//!
//! Defines the [`BuildEventSubscriber`] trait that allows components to
//! receive and process build events.

use crate::events::BuildEvent;
use async_trait::async_trait;
use thiserror::Error;

/// Error type for subscriber operations
#[derive(Debug, Error)]
pub enum SubscriberError {
    /// I/O error occurred during event processing
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Custom error with a message
    #[error("Subscriber error: {0}")]
    Custom(String),
}

/// Trait for components that want to receive build events
///
/// Subscribers receive events through the [`on_event`](BuildEventSubscriber::on_event)
/// method and can perform any processing they need (logging, writing to files,
/// sending over network, etc.).
///
/// Subscribers are responsible for their own serialization format - the
/// events are provided as strongly-typed Rust structs.
///
/// # Example
/// ```
/// use build_events::{BuildEvent, BuildEventSubscriber, SubscriberError};
/// use async_trait::async_trait;
///
/// struct MySubscriber;
///
/// #[async_trait]
/// impl BuildEventSubscriber for MySubscriber {
///     async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
///         println!("Received event: {:?}", event);
///         Ok(())
///     }
///
///     fn name(&self) -> &str {
///         "MySubscriber"
///     }
/// }
/// ```
#[async_trait]
pub trait BuildEventSubscriber: Send + Sync {
    /// Process a build event
    ///
    /// This method is called for each event emitted by the build.
    /// Implementations should return quickly to avoid blocking the dispatcher.
    ///
    /// # Arguments
    /// * `event` - The event to process
    ///
    /// # Errors
    /// Returns a [`SubscriberError`] if event processing fails
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError>;

    /// Get the name of this subscriber for identification
    ///
    /// Used in logging and debugging to identify which subscriber
    /// is processing events.
    fn name(&self) -> &str;

    /// Called when the subscriber is about to be dropped
    ///
    /// This is an optional hook that subscribers can use to perform
    /// cleanup, flush buffers, close files, etc.
    ///
    /// The default implementation does nothing.
    async fn on_close(&self) -> Result<(), SubscriberError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{BuildStarted, build_event, current_millis};

    struct TestSubscriber {
        name: String,
    }

    #[async_trait]
    impl BuildEventSubscriber for TestSubscriber {
        async fn on_event(&self, _event: &BuildEvent) -> Result<(), SubscriberError> {
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_subscriber_trait() {
        let subscriber = TestSubscriber {
            name: "test".to_string(),
        };

        assert_eq!(subscriber.name(), "test");

        let event = BuildEvent {
            event: Some(build_event::Event::BuildStarted(BuildStarted {
                invocation_id: "test-123".to_string(),
                command: "build".to_string(),
                timestamp_millis: current_millis(),
                working_directory: "/tmp".to_string(),
            })),
        };

        let result = subscriber.on_event(&event).await;
        assert!(result.is_ok());

        let close_result = subscriber.on_close().await;
        assert!(close_result.is_ok());
    }
}
