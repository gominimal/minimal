//! Type conversions between Rust and protobuf types
//!
//! This module provides `From` implementations for converting between
//! the pure Rust `build_events` types and the generated protobuf types.

use crate::proto;
use build_events::events;

// ============================================================================
// Rust -> Proto conversions
// ============================================================================

impl From<events::BuildEvent> for proto::BuildEvent {
    fn from(event: events::BuildEvent) -> Self {
        let event = match event {
            events::BuildEvent::BuildStarted(e) => {
                proto::build_event::Event::BuildStarted(e.into())
            }
            events::BuildEvent::BuildFinished(e) => {
                proto::build_event::Event::BuildFinished(e.into())
            }
            events::BuildEvent::TargetStarted(e) => {
                proto::build_event::Event::TargetStarted(e.into())
            }
            events::BuildEvent::TargetCompleted(e) => {
                proto::build_event::Event::TargetCompleted(e.into())
            }
            events::BuildEvent::ActionStarted(e) => {
                proto::build_event::Event::ActionStarted(e.into())
            }
            events::BuildEvent::ActionCompleted(e) => {
                proto::build_event::Event::ActionCompleted(e.into())
            }
        };

        proto::BuildEvent { event: Some(event) }
    }
}

impl From<events::BuildStarted> for proto::BuildStarted {
    fn from(event: events::BuildStarted) -> Self {
        proto::BuildStarted {
            invocation_id: event.invocation_id,
            command: event.command,
            timestamp_millis: event.timestamp_millis,
            working_directory: event.working_directory,
        }
    }
}

impl From<events::BuildFinished> for proto::BuildFinished {
    fn from(event: events::BuildFinished) -> Self {
        proto::BuildFinished {
            invocation_id: event.invocation_id,
            success: event.success,
            timestamp_millis: event.timestamp_millis,
            error_message: event.error_message,
        }
    }
}

impl From<events::TargetStarted> for proto::TargetStarted {
    fn from(event: events::TargetStarted) -> Self {
        proto::TargetStarted {
            target_id: event.target_id,
            label: event.label,
            target_kind: proto::TargetKind::from(event.target_kind) as i32,
            timestamp_millis: event.timestamp_millis,
        }
    }
}

impl From<events::TargetCompleted> for proto::TargetCompleted {
    fn from(event: events::TargetCompleted) -> Self {
        proto::TargetCompleted {
            target_id: event.target_id,
            label: event.label,
            success: event.success,
            timestamp_millis: event.timestamp_millis,
            error_message: event.error_message,
            outputs: event.outputs,
            cache_hit: event.cache_hit,
        }
    }
}

impl From<events::ActionStarted> for proto::ActionStarted {
    fn from(event: events::ActionStarted) -> Self {
        proto::ActionStarted {
            action_id: event.action_id,
            action_name: event.action_name,
            target_id: event.target_id,
            timestamp_millis: event.timestamp_millis,
        }
    }
}

impl From<events::ActionCompleted> for proto::ActionCompleted {
    fn from(event: events::ActionCompleted) -> Self {
        proto::ActionCompleted {
            action_id: event.action_id,
            success: event.success,
            timestamp_millis: event.timestamp_millis,
            exit_code: event.exit_code,
            stdout: event.stdout,
            stderr: event.stderr,
        }
    }
}

impl From<events::TargetKind> for proto::TargetKind {
    fn from(kind: events::TargetKind) -> Self {
        match kind {
            events::TargetKind::Binary => proto::TargetKind::Binary,
            events::TargetKind::Library => proto::TargetKind::Library,
            events::TargetKind::Test => proto::TargetKind::Test,
        }
    }
}

// ============================================================================
// Proto -> Rust conversions
// ============================================================================

impl TryFrom<proto::BuildEvent> for events::BuildEvent {
    type Error = ConversionError;

    fn try_from(event: proto::BuildEvent) -> Result<Self, Self::Error> {
        let event = event.event.ok_or(ConversionError::MissingField("event"))?;

        match event {
            proto::build_event::Event::BuildStarted(e) => {
                Ok(events::BuildEvent::BuildStarted(e.try_into()?))
            }
            proto::build_event::Event::BuildFinished(e) => {
                Ok(events::BuildEvent::BuildFinished(e.try_into()?))
            }
            proto::build_event::Event::TargetStarted(e) => {
                Ok(events::BuildEvent::TargetStarted(e.try_into()?))
            }
            proto::build_event::Event::TargetCompleted(e) => {
                Ok(events::BuildEvent::TargetCompleted(e.try_into()?))
            }
            proto::build_event::Event::ActionStarted(e) => {
                Ok(events::BuildEvent::ActionStarted(e.try_into()?))
            }
            proto::build_event::Event::ActionCompleted(e) => {
                Ok(events::BuildEvent::ActionCompleted(e.try_into()?))
            }
        }
    }
}

impl TryFrom<proto::BuildStarted> for events::BuildStarted {
    type Error = ConversionError;

    fn try_from(event: proto::BuildStarted) -> Result<Self, Self::Error> {
        Ok(events::BuildStarted {
            invocation_id: event.invocation_id,
            command: event.command,
            timestamp_millis: event.timestamp_millis,
            working_directory: event.working_directory,
        })
    }
}

impl TryFrom<proto::BuildFinished> for events::BuildFinished {
    type Error = ConversionError;

    fn try_from(event: proto::BuildFinished) -> Result<Self, Self::Error> {
        Ok(events::BuildFinished {
            invocation_id: event.invocation_id,
            success: event.success,
            timestamp_millis: event.timestamp_millis,
            error_message: event.error_message,
        })
    }
}

impl TryFrom<proto::TargetStarted> for events::TargetStarted {
    type Error = ConversionError;

    fn try_from(event: proto::TargetStarted) -> Result<Self, Self::Error> {
        let target_kind = proto::TargetKind::try_from(event.target_kind)
            .map_err(|_| ConversionError::InvalidEnum("target_kind", event.target_kind))?;

        Ok(events::TargetStarted {
            target_id: event.target_id,
            label: event.label,
            target_kind: target_kind.try_into()?,
            timestamp_millis: event.timestamp_millis,
        })
    }
}

impl TryFrom<proto::TargetCompleted> for events::TargetCompleted {
    type Error = ConversionError;

    fn try_from(event: proto::TargetCompleted) -> Result<Self, Self::Error> {
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
}

impl TryFrom<proto::ActionStarted> for events::ActionStarted {
    type Error = ConversionError;

    fn try_from(event: proto::ActionStarted) -> Result<Self, Self::Error> {
        Ok(events::ActionStarted {
            action_id: event.action_id,
            action_name: event.action_name,
            target_id: event.target_id,
            timestamp_millis: event.timestamp_millis,
        })
    }
}

impl TryFrom<proto::ActionCompleted> for events::ActionCompleted {
    type Error = ConversionError;

    fn try_from(event: proto::ActionCompleted) -> Result<Self, Self::Error> {
        Ok(events::ActionCompleted {
            action_id: event.action_id,
            success: event.success,
            timestamp_millis: event.timestamp_millis,
            exit_code: event.exit_code,
            stdout: event.stdout,
            stderr: event.stderr,
        })
    }
}

impl TryFrom<proto::TargetKind> for events::TargetKind {
    type Error = ConversionError;

    fn try_from(kind: proto::TargetKind) -> Result<Self, Self::Error> {
        match kind {
            proto::TargetKind::Binary => Ok(events::TargetKind::Binary),
            proto::TargetKind::Library => Ok(events::TargetKind::Library),
            proto::TargetKind::Test => Ok(events::TargetKind::Test),
            proto::TargetKind::Unspecified => Err(ConversionError::InvalidEnum("target_kind", 0)),
        }
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

        let proto_event: proto::BuildStarted = rust_event.clone().into();
        let converted_back: events::BuildStarted = proto_event.try_into().unwrap();

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

        let proto_event: proto::BuildEvent = rust_event.clone().into();
        let converted_back: events::BuildEvent = proto_event.try_into().unwrap();

        assert_eq!(rust_event, converted_back);
    }

    #[test]
    fn test_target_kind_conversion() {
        let rust_kind = events::TargetKind::Binary;
        let proto_kind: proto::TargetKind = rust_kind.clone().into();
        let converted_back: events::TargetKind = proto_kind.try_into().unwrap();

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

        let proto_event: proto::BuildFinished = rust_event.clone().into();
        let converted_back: events::BuildFinished = proto_event.try_into().unwrap();

        assert_eq!(rust_event, converted_back);

        // Test with None
        let rust_event_none = events::BuildFinished {
            invocation_id: "test-000".to_string(),
            success: true,
            timestamp_millis: 2222222222,
            error_message: None,
        };

        let proto_event_none: proto::BuildFinished = rust_event_none.clone().into();
        let converted_back_none: events::BuildFinished = proto_event_none.try_into().unwrap();

        assert_eq!(rust_event_none, converted_back_none);
    }
}
