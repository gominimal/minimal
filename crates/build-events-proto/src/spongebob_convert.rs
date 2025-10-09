//! Conversion between build-events Rust types and spongebob proto types
//!
//! This module is only available when the `spongebob-subscriber` feature is enabled.

use build_events::events::{
    ActionCompleted, ActionStarted, BuildEvent, BuildFinished, BuildStarted, TargetCompleted,
    TargetKind, TargetStarted,
};

// Re-export the proto types from the spongebob crate
pub use minimal_spongebob_community_neoeinstein_prost::spongebob::v1 as pb;

/// Convert Rust BuildEvent to spongebob proto BuildEvent
/// Note: This function requires an invocation_id to be passed separately since the
/// Rust BuildEvent enum doesn't carry it at the wrapper level
pub fn to_proto_build_event(event: &BuildEvent, invocation_id: &str) -> pb::BuildEvent {
    match event {
        BuildEvent::BuildStarted(e) => pb::BuildEvent {
            invocation_id: invocation_id.to_string(),
            event: Some(pb::build_event::Event::BuildStarted(
                to_proto_build_started(e),
            )),
        },
        BuildEvent::BuildFinished(e) => pb::BuildEvent {
            invocation_id: invocation_id.to_string(),
            event: Some(pb::build_event::Event::BuildFinished(
                to_proto_build_finished(e),
            )),
        },
        BuildEvent::TargetStarted(e) => pb::BuildEvent {
            invocation_id: invocation_id.to_string(),
            event: Some(pb::build_event::Event::TargetStarted(
                to_proto_target_started(e),
            )),
        },
        BuildEvent::TargetCompleted(e) => pb::BuildEvent {
            invocation_id: invocation_id.to_string(),
            event: Some(pb::build_event::Event::TargetCompleted(
                to_proto_target_completed(e),
            )),
        },
        BuildEvent::ActionStarted(e) => pb::BuildEvent {
            invocation_id: invocation_id.to_string(),
            event: Some(pb::build_event::Event::ActionStarted(
                to_proto_action_started(e),
            )),
        },
        BuildEvent::ActionCompleted(e) => pb::BuildEvent {
            invocation_id: invocation_id.to_string(),
            event: Some(pb::build_event::Event::ActionCompleted(
                to_proto_action_completed(e),
            )),
        },
    }
}

fn to_proto_build_started(e: &BuildStarted) -> pb::BuildStarted {
    pb::BuildStarted {
        invocation_id: e.invocation_id.clone(),
        command: e.command.clone(),
        timestamp_millis: e.timestamp_millis,
        working_directory: e.working_directory.clone(),
    }
}

fn to_proto_build_finished(e: &BuildFinished) -> pb::BuildFinished {
    pb::BuildFinished {
        invocation_id: e.invocation_id.clone(),
        success: e.success,
        timestamp_millis: e.timestamp_millis,
        error_message: e.error_message.clone(),
    }
}

fn to_proto_target_started(e: &TargetStarted) -> pb::TargetStarted {
    pb::TargetStarted {
        target_id: e.target_id.clone(),
        label: e.label.clone(),
        target_kind: to_proto_target_kind(&e.target_kind) as i32,
        timestamp_millis: e.timestamp_millis,
    }
}

fn to_proto_target_completed(e: &TargetCompleted) -> pb::TargetCompleted {
    pb::TargetCompleted {
        target_id: e.target_id.clone(),
        label: e.label.clone(),
        success: e.success,
        timestamp_millis: e.timestamp_millis,
        error_message: e.error_message.clone(),
        outputs: e.outputs.clone(),
        cache_hit: e.cache_hit,
    }
}

fn to_proto_action_started(e: &ActionStarted) -> pb::ActionStarted {
    pb::ActionStarted {
        action_id: e.action_id.clone(),
        action_name: e.action_name.clone(),
        target_id: e.target_id.clone(),
        timestamp_millis: e.timestamp_millis,
    }
}

fn to_proto_action_completed(e: &ActionCompleted) -> pb::ActionCompleted {
    pb::ActionCompleted {
        action_id: e.action_id.clone(),
        success: e.success,
        timestamp_millis: e.timestamp_millis,
        exit_code: e.exit_code,
        stdout: e.stdout.clone(),
        stderr: e.stderr.clone(),
    }
}

fn to_proto_target_kind(kind: &TargetKind) -> pb::TargetKind {
    match kind {
        TargetKind::Binary => pb::TargetKind::Binary,
        TargetKind::Library => pb::TargetKind::Library,
        TargetKind::Test => pb::TargetKind::Test,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use build_events::events::current_millis;

    #[test]
    fn test_build_started_conversion() {
        let rust_event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-123".to_string(),
            command: "build".to_string(),
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        let proto_event: pb::BuildEvent = to_proto_build_event(&rust_event, "test-123");
        assert_eq!(proto_event.invocation_id, "test-123");
        assert!(proto_event.event.is_some());
        match proto_event.event.unwrap() {
            pb::build_event::Event::BuildStarted(e) => {
                assert_eq!(e.invocation_id, "test-123");
                assert_eq!(e.command, "build");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_target_kind_conversion() {
        assert_eq!(
            to_proto_target_kind(&TargetKind::Binary) as i32,
            pb::TargetKind::Binary as i32
        );
        assert_eq!(
            to_proto_target_kind(&TargetKind::Library) as i32,
            pb::TargetKind::Library as i32
        );
        assert_eq!(
            to_proto_target_kind(&TargetKind::Test) as i32,
            pb::TargetKind::Test as i32
        );
    }
}
