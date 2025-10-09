//! JSON file writer subscriber implementation
//!
//! Writes build events to a file in JSON-lines format (one JSON object per line).

use crate::events::BuildEvent;
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

#[async_trait]
impl BuildEventSubscriber for JsonFileWriter {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        let json = serde_json::to_string(event).map_err(|e| {
            SubscriberError::Serialization(format!("Failed to serialize event: {}", e))
        })?;

        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json)?;
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
    use crate::events::{BuildStarted, TargetKind, TargetStarted, current_millis};
    use std::io::{BufRead, BufReader};

    #[tokio::test]
    async fn test_json_file_writer() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.jsonl");

        let writer = JsonFileWriter::new(&file_path).unwrap();
        assert_eq!(writer.name(), "JsonFileWriter");
        assert_eq!(writer.path(), file_path.as_path());

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-123".to_string(),
            command: "build".to_string(),
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

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

        let deserialized: BuildEvent = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(deserialized, event);
    }

    #[tokio::test]
    async fn test_json_file_multiple_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.jsonl");

        let writer = JsonFileWriter::new(&file_path).unwrap();

        let events = vec![
            BuildEvent::BuildStarted(BuildStarted {
                invocation_id: "test-1".to_string(),
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

        for (i, line) in lines.iter().enumerate() {
            let deserialized: BuildEvent = serde_json::from_str(line).unwrap();
            assert_eq!(deserialized, events[i]);
        }
    }

    #[tokio::test]
    async fn test_json_file_truncates_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.jsonl");

        // Write some initial data
        std::fs::write(&file_path, "old data\n").unwrap();

        // Create writer (should truncate)
        let writer = JsonFileWriter::new(&file_path).unwrap();

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "new".to_string(),
            command: "build".to_string(),
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        writer.on_event(&event).await.unwrap();
        writer.on_close().await.unwrap();
        drop(writer);

        // Read back - should only have new data
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(!content.contains("old data"));
        assert!(content.contains("new"));
    }
}
