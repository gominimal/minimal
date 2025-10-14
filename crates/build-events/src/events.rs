//! Build event type definitions
//!
//! This module re-exports protobuf event types from the canonical spongebob.v1 schema
//! as the single source of truth for build events. Proto types are used directly
//! throughout the build-events system for consistency and to eliminate duplication.

// Re-export proto types as the canonical event types
pub use minimal_spongebob_community_neoeinstein_prost::spongebob::v1::{
    build_event, ActionCompleted, ActionStarted, BuildEvent, BuildFinished, BuildMetadata,
    BuildStarted, TargetCompleted, TargetKind, TargetStarted,
};

/// Helper function to get current timestamp in milliseconds
///
/// # Example
/// ```
/// use build_events::events::current_millis;
///
/// let timestamp = current_millis();
/// assert!(timestamp > 0);
/// ```
pub fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_millis() {
        let t1 = current_millis();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = current_millis();
        assert!(t2 > t1);
    }

    #[test]
    fn test_event_construction() {
        let event = BuildEvent {
            invocation_id: "test-123".to_string(),
            event: Some(build_event::Event::BuildStarted(BuildStarted {
                invocation_id: "test-123".to_string(),
                command: "build".to_string(),
                timestamp_millis: 1234567890,
                working_directory: "/tmp".to_string(),
            })),
        };

        assert_eq!(event.invocation_id, "test-123");
        assert!(matches!(
            event.event,
            Some(build_event::Event::BuildStarted(_))
        ));
    }

    #[test]
    fn test_target_kind_values() {
        // Verify proto enum values
        assert_eq!(TargetKind::Unspecified as i32, 0);
        assert_eq!(TargetKind::Binary as i32, 1);
        assert_eq!(TargetKind::Library as i32, 2);
        assert_eq!(TargetKind::Test as i32, 3);
    }
}
