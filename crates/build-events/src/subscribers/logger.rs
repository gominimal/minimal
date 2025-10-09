//! Logger subscriber implementation
//!
//! Logs build events using the tracing crate with structured fields.

use crate::events::BuildEvent;
use crate::subscriber::{BuildEventSubscriber, SubscriberError};
use async_trait::async_trait;
use tracing::info;

/// Subscriber that logs events using the tracing crate
///
/// This subscriber is useful for debugging and development, as it
/// emits structured log entries for each build event.
///
/// # Example
/// ```
/// use build_events::subscribers::LoggerSubscriber;
///
/// let subscriber = LoggerSubscriber::new();
/// ```
#[derive(Debug, Clone)]
pub struct LoggerSubscriber;

impl LoggerSubscriber {
    /// Create a new logger subscriber
    ///
    /// # Example
    /// ```
    /// use build_events::subscribers::LoggerSubscriber;
    ///
    /// let subscriber = LoggerSubscriber::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl Default for LoggerSubscriber {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BuildEventSubscriber for LoggerSubscriber {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        match event {
            BuildEvent::BuildStarted(e) => {
                info!(
                    event = "build_started",
                    invocation_id = %e.invocation_id,
                    command = %e.command,
                    timestamp_millis = e.timestamp_millis,
                    working_directory = %e.working_directory,
                    "Build started"
                );
            }
            BuildEvent::BuildFinished(e) => {
                info!(
                    event = "build_finished",
                    invocation_id = %e.invocation_id,
                    success = e.success,
                    timestamp_millis = e.timestamp_millis,
                    error_message = ?e.error_message,
                    "Build finished"
                );
            }
            BuildEvent::TargetStarted(e) => {
                info!(
                    event = "target_started",
                    label = %e.label,
                    target_kind = ?e.target_kind,
                    timestamp_millis = e.timestamp_millis,
                    "Target started"
                );
            }
            BuildEvent::TargetCompleted(e) => {
                info!(
                    event = "target_completed",
                    label = %e.label,
                    success = e.success,
                    timestamp_millis = e.timestamp_millis,
                    error_message = ?e.error_message,
                    outputs = ?e.outputs,
                    "Target completed"
                );
            }
            BuildEvent::ActionStarted(e) => {
                info!(
                    event = "action_started",
                    action_id = %e.action_id,
                    action_name = %e.action_name,
                    target_id = %e.target_id,
                    timestamp_millis = e.timestamp_millis,
                    "Action started"
                );
            }
            BuildEvent::ActionCompleted(e) => {
                info!(
                    event = "action_completed",
                    action_id = %e.action_id,
                    success = e.success,
                    timestamp_millis = e.timestamp_millis,
                    exit_code = e.exit_code,
                    stdout = ?e.stdout,
                    stderr = ?e.stderr,
                    "Action completed"
                );
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "LoggerSubscriber"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{BuildStarted, TargetKind, TargetStarted, current_millis};

    #[tokio::test]
    async fn test_logger_subscriber() {
        let subscriber = LoggerSubscriber::new();
        assert_eq!(subscriber.name(), "LoggerSubscriber");

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-123".to_string(),
            command: "build".to_string(),
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        let result = subscriber.on_event(&event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_logger_all_event_types() {
        let subscriber = LoggerSubscriber::new();

        let events = vec![
            BuildEvent::BuildStarted(BuildStarted {
                invocation_id: "test".to_string(),
                command: "build".to_string(),
                timestamp_millis: current_millis(),
                working_directory: "/tmp".to_string(),
            }),
            BuildEvent::TargetStarted(TargetStarted {
                target_id: "target-1".to_string(),
                label: "//foo:bar".to_string(),
                target_kind: TargetKind::Binary,
                timestamp_millis: current_millis(),
            }),
        ];

        for event in events {
            let result = subscriber.on_event(&event).await;
            assert!(result.is_ok());
        }
    }
}
