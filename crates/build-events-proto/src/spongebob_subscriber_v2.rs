//! Subscriber that sends build events to Spongebob service

use async_trait::async_trait;
use build_events::{BuildEvent, BuildEventSubscriber, SubscriberError};
use tracing::warn;

/// Subscriber that publishes build events to Spongebob service
///
/// This subscriber uses the `SpongeBob` client to connect to the
/// Spongebob service and publish build events via bidirectional streaming.
///
/// # Example
/// ```ignore
/// use build_events_proto::{SpongeBob, SpongeBobSubscriberV2};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Create a spongebob client (opens stream and gets server-assigned ID)
///     let spongebob = SpongeBob::new().await?;
///
///     // Create subscriber from the client
///     let subscriber = SpongeBobSubscriberV2::from_client(spongebob);
///
///     // Use with BuildEventDispatcher
///     // dispatcher.add_subscriber(Box::new(subscriber));
///     Ok(())
/// }
/// ```
pub struct SpongeBobSubscriberV2 {
    spongebob: std::sync::Arc<crate::client::SpongeBob>,
}

impl SpongeBobSubscriberV2 {
    /// Create subscriber from an existing SpongeBob client
    ///
    /// # Arguments
    /// * `client` - An existing SpongeBob client with active streaming connection
    ///
    /// # Example
    /// ```ignore
    /// # use build_events_proto::{SpongeBob, SpongeBobSubscriberV2};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let spongebob = SpongeBob::new().await?;
    /// let subscriber = SpongeBobSubscriberV2::from_client(spongebob);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_client(client: crate::client::SpongeBob) -> Self {
        Self {
            spongebob: std::sync::Arc::new(client),
        }
    }
}

#[async_trait]
impl BuildEventSubscriber for SpongeBobSubscriberV2 {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        // Publish all events to SpongeBob
        match self.spongebob.publish_build_event(event.clone()).await {
            Ok(()) => {
                tracing::debug!("Successfully published build event to Spongebob");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to publish build event to Spongebob: {}", e);
                Err(SubscriberError::Custom(format!(
                    "Failed to publish event: {}",
                    e
                )))
            }
        }
    }

    fn name(&self) -> &str {
        "SpongeBobSubscriberV2"
    }

    async fn on_close(&self) -> Result<(), SubscriberError> {
        // No cleanup needed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_subscriber_creation() {
        // This test would require a mock SpongeBobInvocation
        // For now, just ensure the module compiles
    }
}
