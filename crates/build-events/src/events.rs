//! Build event type definitions
//!
//! This module defines the core event types emitted during a build.
//! Events are strongly-typed Rust enums and structs with serde support
//! for easy serialization to JSON, protobuf, or other formats.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main build event enum that wraps all possible event types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuildEvent {
    /// Build process started
    BuildStarted(BuildStarted),
    /// Build process finished
    BuildFinished(BuildFinished),
    /// Target started building
    TargetStarted(TargetStarted),
    /// Target completed building
    TargetCompleted(TargetCompleted),
    /// Action started executing
    ActionStarted(ActionStarted),
    /// Action completed executing
    ActionCompleted(ActionCompleted),
    /// Build metadata (user, branch, commit, etc.)
    BuildMetadata(BuildMetadata),
}

/// Event emitted when a build starts
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BuildStarted {
    /// Unique identifier for this build invocation
    pub invocation_id: String,
    /// Command string for display
    pub command: String,
    /// Unix timestamp in milliseconds
    pub timestamp_millis: i64,
    /// Working directory where build was started
    pub working_directory: String,
}

/// Event emitted when a build finishes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BuildFinished {
    /// Unique identifier for this build invocation
    pub invocation_id: String,
    /// Whether the build succeeded
    pub success: bool,
    /// Unix timestamp in milliseconds
    pub timestamp_millis: i64,
    /// Optional error message if build failed
    pub error_message: Option<String>,
}

/// Event emitted when a target starts building
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetStarted {
    /// Unique identifier for this target
    pub target_id: String,
    /// Target label (e.g., "//foo:bar")
    pub label: String,
    /// Type of target being built
    pub target_kind: TargetKind,
    /// Unix timestamp in milliseconds
    pub timestamp_millis: i64,
}

/// Event emitted when a target completes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetCompleted {
    /// Unique identifier for this target (must match TargetStarted.target_id)
    pub target_id: String,
    /// Target label (e.g., "//foo:bar")
    pub label: String,
    /// Whether the target built successfully
    pub success: bool,
    /// Unix timestamp in milliseconds
    pub timestamp_millis: i64,
    /// Optional error message if target failed
    pub error_message: Option<String>,
    /// Paths to generated output files
    pub outputs: Vec<String>,
    /// Whether this target was served from cache
    pub cache_hit: bool,
}

/// Event emitted when an action starts executing
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ActionStarted {
    /// Unique identifier for this action
    pub action_id: String,
    /// Human-readable name for the action (e.g., "CppCompile", "Link")
    pub action_name: String,
    /// Target this action belongs to (if any)
    pub target_id: String,
    /// Unix timestamp in milliseconds
    pub timestamp_millis: i64,
}

/// Event emitted when an action completes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ActionCompleted {
    /// Unique identifier for this action
    pub action_id: String,
    /// Whether the action succeeded
    pub success: bool,
    /// Unix timestamp in milliseconds
    pub timestamp_millis: i64,
    /// Exit code of the action
    pub exit_code: i32,
    /// Optional stdout from the action
    pub stdout: Option<String>,
    /// Optional stderr from the action
    pub stderr: Option<String>,
}

/// Event containing arbitrary key-value metadata about the build environment
/// Standard keys: "user", "branch", "commit", "repo_url"
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BuildMetadata {
    /// Metadata key-value pairs
    pub metadata: HashMap<String, String>,
}

/// Type of build target
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Binary executable target
    Binary,
    /// Library target
    Library,
    /// Test target
    Test,
}

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
    fn test_event_serialization() {
        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-123".to_string(),
            command: "build".to_string(),
            timestamp_millis: 1234567890,
            working_directory: "/tmp".to_string(),
        });

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: BuildEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_target_kind_serialization() {
        let kind = TargetKind::Binary;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"binary\"");
    }
}
