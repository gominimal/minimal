//! Subscriber that sends build events to Spongebob service using the workspace spongebob crate

#[cfg(feature = "spongebob-subscriber")]
use async_trait::async_trait;
#[cfg(feature = "spongebob-subscriber")]
use build_events::{BuildEvent, BuildEventSubscriber, SubscriberError};
#[cfg(feature = "spongebob-subscriber")]
use tracing::warn;

#[cfg(feature = "spongebob-subscriber")]
use crate::spongebob_convert::to_proto_build_event;

/// Subscriber that publishes build events to Spongebob service
///
/// This subscriber uses the workspace `spongebob` crate to connect to the
/// Spongebob service and publish build events.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "spongebob-subscriber")]
/// use build_events_proto::SpongeBobSubscriberV2;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Create a spongebob client and invocation
///     let mut spongebob = spongebob::SpongeBob::new().await?;
///     let invocation = spongebob.create_invocation("my-build").await?;
///
///     // Create subscriber from the invocation
///     let subscriber = SpongeBobSubscriberV2::from_invocation(invocation);
///
///     // Use with BuildEventDispatcher
///     // dispatcher.add_subscriber(Box::new(subscriber));
///     Ok(())
/// }
/// ```
#[cfg(feature = "spongebob-subscriber")]
pub struct SpongeBobSubscriberV2 {
    invocation: std::sync::Arc<tokio::sync::Mutex<spongebob::SpongeBobInvocation>>,
}

#[cfg(feature = "spongebob-subscriber")]
impl SpongeBobSubscriberV2 {
    /// Create subscriber from an existing SpongeBobInvocation
    ///
    /// # Arguments
    /// * `invocation` - An existing SpongeBobInvocation to publish events to
    ///
    /// # Example
    /// ```no_run
    /// # #[cfg(feature = "spongebob-subscriber")]
    /// # use build_events_proto::SpongeBobSubscriberV2;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut spongebob = spongebob::SpongeBob::new().await?;
    /// let invocation = spongebob.create_invocation("my-build").await?;
    /// let subscriber = SpongeBobSubscriberV2::from_invocation(invocation);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_invocation(invocation: spongebob::SpongeBobInvocation) -> Self {
        Self {
            invocation: std::sync::Arc::new(tokio::sync::Mutex::new(invocation)),
        }
    }
}

#[cfg(feature = "spongebob-subscriber")]
#[async_trait]
impl BuildEventSubscriber for SpongeBobSubscriberV2 {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        // Get lock on invocation
        let mut invocation = self.invocation.lock().await;

        // Convert Rust event to proto (need invocation_id from the invocation)
        let proto_event = to_proto_build_event(event, invocation.invocation_id());

        // Publish event
        match invocation.publish_build_event(proto_event).await {
            Ok(()) => {
                tracing::debug!("Successfully published build event to Spongebob");
                Ok(())
            }
            Err(e) => {
                // Log warning but don't fail the build
                warn!("Failed to publish build event to Spongebob: {}", e);
                // Return error so dispatcher can decide how to handle it
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

#[cfg(all(test, feature = "spongebob-subscriber"))]
mod tests {
    #[test]
    fn test_subscriber_creation() {
        // This test would require a mock SpongeBobInvocation
        // For now, just ensure the module compiles
    }
}
