//! Subscriber that sends build events to Spongebob service using the workspace spongebob crate

#[cfg(feature = "spongebob-subscriber")]
use async_trait::async_trait;
#[cfg(feature = "spongebob-subscriber")]
use build_events::{BuildEvent, BuildEventSubscriber, SubscriberError};
#[cfg(feature = "spongebob-subscriber")]
use tracing::warn;

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
///     let invocation = spongebob.create_invocation();
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
    /// Cache of file paths from BuildMetadata events, keyed by "{target_id}/stdout_path" etc.
    file_paths: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
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
    /// let invocation = spongebob.create_invocation();
    /// let subscriber = SpongeBobSubscriberV2::from_invocation(invocation);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_invocation(invocation: spongebob::SpongeBobInvocation) -> Self {
        Self {
            invocation: std::sync::Arc::new(tokio::sync::Mutex::new(invocation)),
            file_paths: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }
}

#[cfg(feature = "spongebob-subscriber")]
#[async_trait]
impl BuildEventSubscriber for SpongeBobSubscriberV2 {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        use build_events::events::build_event::Event;

        // Handle BuildMetadata events to cache file paths
        if let Some(Event::BuildMetadata(metadata)) = &event.event {
            let mut file_paths = self.file_paths.lock().await;
            for (key, value) in &metadata.metadata {
                if key.ends_with("_path") {
                    file_paths.insert(key.clone(), value.clone());
                }
            }
            // Don't publish BuildMetadata with file paths to avoid clutter
            return Ok(());
        }

        // Handle TargetCompleted events with file uploads
        if let Some(Event::TargetCompleted(target_completed)) = &event.event {
            let target_id = &target_completed.target_id;

            // Get file paths from cache
            let file_paths = self.file_paths.lock().await;
            let stdout_key = format!("{}/stdout_path", target_id);
            let stderr_key = format!("{}/stderr_path", target_id);

            let stdout_path = file_paths.get(&stdout_key);
            let stderr_path = file_paths.get(&stderr_key);

            // First publish the TargetCompleted event
            let mut invocation = self.invocation.lock().await;
            if let Err(e) = invocation.publish_build_event(event.clone()).await {
                warn!("Failed to publish TargetCompleted event to Spongebob: {}", e);
                return Err(SubscriberError::Custom(format!(
                    "Failed to publish TargetCompleted event: {}",
                    e
                )));
            }

            // Then upload files if paths are available
            if let Some(stdout_path) = stdout_path {
                if let Ok(contents) = std::fs::read(stdout_path) {
                    if let Err(e) = invocation.publish_file_created_event(target_id, "stdout", contents).await {
                        warn!("Failed to upload stdout for target {}: {}", target_id, e);
                    }
                } else {
                    warn!("Failed to read stdout file: {}", stdout_path);
                }
            }

            if let Some(stderr_path) = stderr_path {
                if let Ok(contents) = std::fs::read(stderr_path) {
                    if let Err(e) = invocation.publish_file_created_event(target_id, "stderr", contents).await {
                        warn!("Failed to upload stderr for target {}: {}", target_id, e);
                    }
                } else {
                    warn!("Failed to read stderr file: {}", stderr_path);
                }
            }

            drop(invocation);
            return Ok(());
        }

        // For all other events, just publish them
        let mut invocation = self.invocation.lock().await;
        match invocation.publish_build_event(event.clone()).await {
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

#[cfg(all(test, feature = "spongebob-subscriber"))]
mod tests {
    #[test]
    fn test_subscriber_creation() {
        // This test would require a mock SpongeBobInvocation
        // For now, just ensure the module compiles
    }
}
