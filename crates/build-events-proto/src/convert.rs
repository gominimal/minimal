//! Type conversions between Rust and protobuf types
//!
//! This module provides conversion functions between the pure Rust `build_events`
//! types and the BSR-generated canonical protobuf types from spongebob.v1.
//!
//! # Extension Trait
//!
//! For ergonomic conversion, use the [`ToProto`] trait which provides a `.to_proto()` method:
//!
//! ```
//! use build_events::events::{BuildStarted, BuildEvent};
//! use build_events_proto::convert::ToProto;
//!
//! let event = BuildEvent::BuildStarted(BuildStarted {
//!     invocation_id: "test-123".to_string(),
//!     command: "build".to_string(),
//!     timestamp_millis: 123456789,
//!     working_directory: "/tmp".to_string(),
//! });
//!
//! let proto_event = event.to_proto("test-123");
//! ```

use crate::proto;
use build_events::events;

// ============================================================================
// Rust -> Proto conversions
// ============================================================================

/// Convert Rust BuildEvent to proto BuildEvent with invocation_id at wrapper level
///
/// The canonical spongebob proto has `invocation_id` both at the BuildEvent wrapper level
/// and inside each event type. This function ensures the wrapper-level invocation_id is set.
pub fn to_proto_build_event(event: &events::BuildEvent, invocation_id: &str) -> proto::BuildEvent {
    let proto_event = match event {
        events::BuildEvent::BuildStarted(e) => {
            proto::build_event::Event::BuildStarted(to_proto_build_started(e))
        }
        events::BuildEvent::BuildFinished(e) => {
            proto::build_event::Event::BuildFinished(to_proto_build_finished(e))
        }
        events::BuildEvent::TargetStarted(e) => {
            proto::build_event::Event::TargetStarted(to_proto_target_started(e))
        }
        events::BuildEvent::TargetCompleted(e) => {
            proto::build_event::Event::TargetCompleted(to_proto_target_completed(e))
        }
        events::BuildEvent::ActionStarted(e) => {
            proto::build_event::Event::ActionStarted(to_proto_action_started(e))
        }
        events::BuildEvent::ActionCompleted(e) => {
            proto::build_event::Event::ActionCompleted(to_proto_action_completed(e))
        }
        events::BuildEvent::BuildMetadata(e) => {
            proto::build_event::Event::BuildMetadata(to_proto_build_metadata(e))
        }
    };

    proto::BuildEvent {
        invocation_id: invocation_id.to_string(),
        event: Some(proto_event),
    }
}

pub fn to_proto_build_started(event: &events::BuildStarted) -> proto::BuildStarted {
    proto::BuildStarted {
        invocation_id: event.invocation_id.clone(),
        command: event.command.clone(),
        timestamp_millis: event.timestamp_millis,
        working_directory: event.working_directory.clone(),
    }
}

pub fn to_proto_build_finished(event: &events::BuildFinished) -> proto::BuildFinished {
    proto::BuildFinished {
        invocation_id: event.invocation_id.clone(),
        success: event.success,
        timestamp_millis: event.timestamp_millis,
        error_message: event.error_message.clone(),
    }
}

pub fn to_proto_target_started(event: &events::TargetStarted) -> proto::TargetStarted {
    proto::TargetStarted {
        target_id: event.target_id.clone(),
        label: event.label.clone(),
        target_kind: to_proto_target_kind(&event.target_kind) as i32,
        timestamp_millis: event.timestamp_millis,
    }
}

pub fn to_proto_target_completed(event: &events::TargetCompleted) -> proto::TargetCompleted {
    proto::TargetCompleted {
        target_id: event.target_id.clone(),
        label: event.label.clone(),
        success: event.success,
        timestamp_millis: event.timestamp_millis,
        error_message: event.error_message.clone(),
        outputs: event.outputs.clone(),
        cache_hit: event.cache_hit,
    }
}

pub fn to_proto_action_started(event: &events::ActionStarted) -> proto::ActionStarted {
    proto::ActionStarted {
        action_id: event.action_id.clone(),
        action_name: event.action_name.clone(),
        target_id: event.target_id.clone(),
        timestamp_millis: event.timestamp_millis,
    }
}

pub fn to_proto_action_completed(event: &events::ActionCompleted) -> proto::ActionCompleted {
    proto::ActionCompleted {
        action_id: event.action_id.clone(),
        success: event.success,
        timestamp_millis: event.timestamp_millis,
        exit_code: event.exit_code,
        stdout: event.stdout.clone(),
        stderr: event.stderr.clone(),
    }
}

pub fn to_proto_build_metadata(event: &events::BuildMetadata) -> proto::BuildMetadata {
    proto::BuildMetadata {
        metadata: event.metadata.clone(),
    }
}

pub fn to_proto_target_kind(kind: &events::TargetKind) -> proto::TargetKind {
    match kind {
        events::TargetKind::Binary => proto::TargetKind::Binary,
        events::TargetKind::Library => proto::TargetKind::Library,
        events::TargetKind::Test => proto::TargetKind::Test,
    }
}

// ============================================================================
// Proto -> Rust conversions
// ============================================================================

pub fn from_proto_build_event(
    event: proto::BuildEvent,
) -> Result<events::BuildEvent, ConversionError> {
    let event = event.event.ok_or(ConversionError::MissingField("event"))?;

    match event {
        proto::build_event::Event::BuildStarted(e) => Ok(events::BuildEvent::BuildStarted(
            from_proto_build_started(e)?,
        )),
        proto::build_event::Event::BuildFinished(e) => Ok(events::BuildEvent::BuildFinished(
            from_proto_build_finished(e)?,
        )),
        proto::build_event::Event::TargetStarted(e) => Ok(events::BuildEvent::TargetStarted(
            from_proto_target_started(e)?,
        )),
        proto::build_event::Event::TargetCompleted(e) => Ok(events::BuildEvent::TargetCompleted(
            from_proto_target_completed(e)?,
        )),
        proto::build_event::Event::ActionStarted(e) => Ok(events::BuildEvent::ActionStarted(
            from_proto_action_started(e)?,
        )),
        proto::build_event::Event::ActionCompleted(e) => Ok(events::BuildEvent::ActionCompleted(
            from_proto_action_completed(e)?,
        )),
        proto::build_event::Event::BuildMetadata(e) => Ok(events::BuildEvent::BuildMetadata(
            from_proto_build_metadata(e)?,
        )),
    }
}

pub fn from_proto_build_started(
    event: proto::BuildStarted,
) -> Result<events::BuildStarted, ConversionError> {
    Ok(events::BuildStarted {
        invocation_id: event.invocation_id,
        command: event.command,
        timestamp_millis: event.timestamp_millis,
        working_directory: event.working_directory,
    })
}

pub fn from_proto_build_finished(
    event: proto::BuildFinished,
) -> Result<events::BuildFinished, ConversionError> {
    Ok(events::BuildFinished {
        invocation_id: event.invocation_id,
        success: event.success,
        timestamp_millis: event.timestamp_millis,
        error_message: event.error_message,
    })
}

pub fn from_proto_target_started(
    event: proto::TargetStarted,
) -> Result<events::TargetStarted, ConversionError> {
    let target_kind = proto::TargetKind::try_from(event.target_kind)
        .map_err(|_| ConversionError::InvalidEnum("target_kind", event.target_kind))?;

    Ok(events::TargetStarted {
        target_id: event.target_id,
        label: event.label,
        target_kind: from_proto_target_kind(target_kind)?,
        timestamp_millis: event.timestamp_millis,
    })
}

pub fn from_proto_target_completed(
    event: proto::TargetCompleted,
) -> Result<events::TargetCompleted, ConversionError> {
    Ok(events::TargetCompleted {
        target_id: event.target_id,
        label: event.label,
        success: event.success,
        timestamp_millis: event.timestamp_millis,
        error_message: event.error_message,
        outputs: event.outputs,
        cache_hit: event.cache_hit,
    })
}

pub fn from_proto_action_started(
    event: proto::ActionStarted,
) -> Result<events::ActionStarted, ConversionError> {
    Ok(events::ActionStarted {
        action_id: event.action_id,
        action_name: event.action_name,
        target_id: event.target_id,
        timestamp_millis: event.timestamp_millis,
    })
}

pub fn from_proto_action_completed(
    event: proto::ActionCompleted,
) -> Result<events::ActionCompleted, ConversionError> {
    Ok(events::ActionCompleted {
        action_id: event.action_id,
        success: event.success,
        timestamp_millis: event.timestamp_millis,
        exit_code: event.exit_code,
        stdout: event.stdout,
        stderr: event.stderr,
    })
}

pub fn from_proto_build_metadata(
    event: proto::BuildMetadata,
) -> Result<events::BuildMetadata, ConversionError> {
    Ok(events::BuildMetadata {
        metadata: event.metadata,
    })
}

pub fn from_proto_target_kind(
    kind: proto::TargetKind,
) -> Result<events::TargetKind, ConversionError> {
    match kind {
        proto::TargetKind::Binary => Ok(events::TargetKind::Binary),
        proto::TargetKind::Library => Ok(events::TargetKind::Library),
        proto::TargetKind::Test => Ok(events::TargetKind::Test),
        proto::TargetKind::Unspecified => Err(ConversionError::InvalidEnum("target_kind", 0)),
    }
}

// ============================================================================
// Extension Trait for Ergonomic Conversion
// ============================================================================

/// Extension trait providing ergonomic `.to_proto()` method for build events
///
/// This trait provides a convenient way to convert Rust build events to protobuf
/// format with method syntax instead of calling standalone functions.
///
/// # Example
///
/// ```
/// use build_events::events::{BuildStarted, BuildEvent, current_millis};
/// use build_events_proto::convert::ToProto;
///
/// let event = BuildEvent::BuildStarted(BuildStarted {
///     invocation_id: "test-123".to_string(),
///     command: "build".to_string(),
///     timestamp_millis: current_millis(),
///     working_directory: "/tmp".to_string(),
/// });
///
/// // Ergonomic method syntax
/// let proto_event = event.to_proto("test-123");
/// ```
pub trait ToProto {
    /// Convert this event to a protobuf BuildEvent with the specified invocation_id
    ///
    /// The invocation_id is required because the canonical spongebob proto has
    /// `invocation_id` at the BuildEvent wrapper level, separate from the inner
    /// event types.
    fn to_proto(&self, invocation_id: &str) -> proto::BuildEvent;
}

impl ToProto for events::BuildEvent {
    fn to_proto(&self, invocation_id: &str) -> proto::BuildEvent {
        to_proto_build_event(self, invocation_id)
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Error that can occur during type conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Invalid enum value for {0}: {1}")]
    InvalidEnum(&'static str, i32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_started_round_trip() {
        let rust_event = events::BuildStarted {
            invocation_id: "test-123".to_string(),
            command: "build".to_string(),
            timestamp_millis: 1234567890,
            working_directory: "/tmp".to_string(),
        };

        let proto_event = to_proto_build_started(&rust_event);
        let converted_back = from_proto_build_started(proto_event).unwrap();

        assert_eq!(rust_event, converted_back);
    }

    #[test]
    fn test_build_event_round_trip() {
        let rust_event = events::BuildEvent::BuildStarted(events::BuildStarted {
            invocation_id: "test-456".to_string(),
            command: "test".to_string(),
            timestamp_millis: 9876543210,
            working_directory: "/home/user".to_string(),
        });

        let proto_event = to_proto_build_event(&rust_event, "test-456");
        let converted_back = from_proto_build_event(proto_event).unwrap();

        assert_eq!(rust_event, converted_back);
    }

    #[test]
    fn test_target_kind_conversion() {
        let rust_kind = events::TargetKind::Binary;
        let proto_kind = to_proto_target_kind(&rust_kind);
        let converted_back = from_proto_target_kind(proto_kind).unwrap();

        assert_eq!(rust_kind, converted_back);
    }

    #[test]
    fn test_optional_fields() {
        let rust_event = events::BuildFinished {
            invocation_id: "test-789".to_string(),
            success: false,
            timestamp_millis: 1111111111,
            error_message: Some("build failed".to_string()),
        };

        let proto_event = to_proto_build_finished(&rust_event);
        let converted_back = from_proto_build_finished(proto_event).unwrap();

        assert_eq!(rust_event, converted_back);

        // Test with None
        let rust_event_none = events::BuildFinished {
            invocation_id: "test-000".to_string(),
            success: true,
            timestamp_millis: 2222222222,
            error_message: None,
        };

        let proto_event_none = to_proto_build_finished(&rust_event_none);
        let converted_back_none = from_proto_build_finished(proto_event_none).unwrap();

        assert_eq!(rust_event_none, converted_back_none);
    }
}
