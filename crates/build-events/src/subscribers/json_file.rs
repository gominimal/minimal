//! JSON file writer subscriber implementation
//!
//! Writes build events to a file in JSON-lines format (one JSON object per line).

use crate::events::{build_event, BuildEvent, TargetKind};
use crate::subscriber::{BuildEventSubscriber, SubscriberError};
use async_trait::async_trait;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Subscriber that writes events to a JSON-lines file
///
/// Each event is serialized to JSON and written as a single line to the file.
/// The file is automatically flushed after each write to ensure durability.
///
/// # Example
/// ```no_run
/// use build_events::subscribers::JsonFileWriter;
///
/// let writer = JsonFileWriter::new("build_events.jsonl").unwrap();
/// ```
pub struct JsonFileWriter {
    file: Mutex<std::fs::File>,
    path: PathBuf,
}

impl JsonFileWriter {
    /// Create a new JSON file writer
    ///
    /// Creates or truncates the file at the specified path. The file will
    /// be written in JSON-lines format (one event per line).
    ///
    /// # Arguments
    /// * `path` - Path to the output file
    ///
    /// # Errors
    /// Returns an error if the file cannot be created or opened
    ///
    /// # Example
    /// ```no_run
    /// use build_events::subscribers::JsonFileWriter;
    ///
    /// let writer = JsonFileWriter::new("build_events.jsonl").unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = std::fs::File::create(&path)?;

        Ok(Self {
            file: Mutex::new(file),
            path,
        })
    }

    /// Get the path to the output file
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for JsonFileWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonFileWriter")
            .field("path", &self.path)
            .finish()
    }
}

/// Convert proto BuildEvent to JSON value (custom serialization since proto types don't have serde)
fn event_to_json(event: &BuildEvent) -> serde_json::Value {
    let event_type_json = match &event.event {
        Some(build_event::Event::BuildStarted(e)) => {
            serde_json::json!({
                "type": "build_started",
                "build_started": {
                    "command": e.command,
                    "timestamp_millis": e.timestamp_millis,
                    "working_directory": e.working_directory,
                }
            })
        }
        Some(build_event::Event::BuildFinished(e)) => {
            serde_json::json!({
                "type": "build_finished",
                "build_finished": {
                    "success": e.success,
                    "timestamp_millis": e.timestamp_millis,
                    "error_message": e.error_message,
                }
            })
        }
        Some(build_event::Event::TargetStarted(e)) => {
            let target_kind = match TargetKind::try_from(e.target_kind) {
                Ok(TargetKind::Binary) => "binary",
                Ok(TargetKind::Library) => "library",
                Ok(TargetKind::Test) => "test",
                _ => "unspecified",
            };
            serde_json::json!({
                "type": "target_started",
                "target_started": {
                    "target_id": e.target_id,
                    "label": e.label,
                    "target_kind": target_kind,
                    "timestamp_millis": e.timestamp_millis,
                }
            })
        }
        Some(build_event::Event::TargetCompleted(e)) => {
            serde_json::json!({
                "type": "target_completed",
                "target_completed": {
                    "target_id": e.target_id,
                    "label": e.label,
                    "success": e.success,
                    "timestamp_millis": e.timestamp_millis,
                    "error_message": e.error_message,
                    "outputs": e.outputs,
                    "cache_hit": e.cache_hit,
                }
            })
        }
        Some(build_event::Event::ActionStarted(e)) => {
            serde_json::json!({
                "type": "action_started",
                "action_started": {
                    "action_id": e.action_id,
                    "action_name": e.action_name,
                    "target_id": e.target_id,
                    "timestamp_millis": e.timestamp_millis,
                }
            })
        }
        Some(build_event::Event::ActionCompleted(e)) => {
            serde_json::json!({
                "type": "action_completed",
                "action_completed": {
                    "action_id": e.action_id,
                    "success": e.success,
                    "timestamp_millis": e.timestamp_millis,
                    "exit_code": e.exit_code,
                    "stdout": e.stdout,
                    "stderr": e.stderr,
                }
            })
        }
        Some(build_event::Event::BuildMetadata(e)) => {
            serde_json::json!({
                "type": "build_metadata",
                "build_metadata": {
                    "metadata": e.metadata,
                }
            })
        }
        Some(build_event::Event::FileCreated(e)) => {
            serde_json::json!({
                "type": "file_created",
                "file_created": {
                    "target_id": e.target_id,
                    "name": e.name,
                    "size": e.contents.len(),
                    "timestamp_millis": e.timestamp_millis,
                }
            })
        }
        None => {
            serde_json::json!({
                "type": "unknown",
            })
        }
    };

    event_type_json
}

#[async_trait]
impl BuildEventSubscriber for JsonFileWriter {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        let json = event_to_json(event);
        let json_string = serde_json::to_string(&json).map_err(|e| {
            SubscriberError::Serialization(format!("Failed to serialize event: {}", e))
        })?;

        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json_string)?;
        file.flush()?;

        Ok(())
    }

    fn name(&self) -> &str {
        "JsonFileWriter"
    }

    async fn on_close(&self) -> Result<(), SubscriberError> {
        let mut file = self.file.lock().unwrap();
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{BuildStarted, TargetStarted, current_millis};
    use std::io::{BufRead, BufReader};

    #[tokio::test]
    async fn test_json_file_writer() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.jsonl");

        let writer = JsonFileWriter::new(&file_path).unwrap();
        assert_eq!(writer.name(), "JsonFileWriter");
        assert_eq!(writer.path(), file_path.as_path());

        let event = BuildEvent {
            invocation_id: "test-123".to_string(),
            event: Some(build_event::Event::BuildStarted(BuildStarted {
                invocation_id: "test-123".to_string(),
                command: "build".to_string(),
                timestamp_millis: current_millis(),
                working_directory: "/tmp".to_string(),
            })),
        };

        let result = writer.on_event(&event).await;
        assert!(result.is_ok());

        // Close and flush
        writer.on_close().await.unwrap();
        drop(writer);

        // Read back and verify
        let file = std::fs::File::open(&file_path).unwrap();
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

        assert_eq!(lines.len(), 1);

        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed["invocation_id"], "test-123");
        assert_eq!(parsed["event"]["type"], "build_started");
    }

    #[tokio::test]
    async fn test_json_file_multiple_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.jsonl");

        let writer = JsonFileWriter::new(&file_path).unwrap();

        let events = vec![
            BuildEvent {
                invocation_id: "test-1".to_string(),
                event: Some(build_event::Event::BuildStarted(BuildStarted {
                    invocation_id: "test-1".to_string(),
                    command: "build".to_string(),
                    timestamp_millis: current_millis(),
                    working_directory: "/tmp".to_string(),
                })),
            },
            BuildEvent {
                invocation_id: "test-1".to_string(),
                event: Some(build_event::Event::TargetStarted(TargetStarted {
                    target_id: "target-1".to_string(),
                    label: "//foo:bar".to_string(),
                    target_kind: TargetKind::Binary as i32,
                    timestamp_millis: current_millis(),
                })),
            },
        ];

        for event in &events {
            writer.on_event(event).await.unwrap();
        }

        writer.on_close().await.unwrap();
        drop(writer);

        // Read back and verify
        let file = std::fs::File::open(&file_path).unwrap();
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

        assert_eq!(lines.len(), 2);

        let parsed0: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed0["event"]["type"], "build_started");

        let parsed1: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(parsed1["event"]["type"], "target_started");
    }

    #[tokio::test]
    async fn test_json_file_truncates_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.jsonl");

        // Write some initial data
        std::fs::write(&file_path, "old data\n").unwrap();

        // Create writer (should truncate)
        let writer = JsonFileWriter::new(&file_path).unwrap();

        let event = BuildEvent {
            invocation_id: "new".to_string(),
            event: Some(build_event::Event::BuildStarted(BuildStarted {
                invocation_id: "new".to_string(),
                command: "build".to_string(),
                timestamp_millis: current_millis(),
                working_directory: "/tmp".to_string(),
            })),
        };

        writer.on_event(&event).await.unwrap();
        writer.on_close().await.unwrap();
        drop(writer);

        // Read back - should only have new data
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(!content.contains("old data"));
        assert!(content.contains("new"));
    }
}
