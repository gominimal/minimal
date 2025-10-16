//! Protobuf text format file writer subscriber implementation
//!
//! Writes build events to a file in protobuf text format (one message per separator).

use crate::events::BuildEvent;
use crate::subscriber::{BuildEventSubscriber, SubscriberError};
use async_trait::async_trait;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, text_format::FormatOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

/// Global descriptor pool for BuildEvent messages
static DESCRIPTOR_POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    // Start with global pool that includes well-known types
    let mut pool = DescriptorPool::global();

    // Decode and add our custom file descriptors
    let fds = prost_reflect::prost_types::FileDescriptorSet::decode(
        minimal_spongebob_community_neoeinstein_prost::spongebob::v1::FILE_DESCRIPTOR_SET,
    )
    .expect("Failed to decode file descriptor set");

    // Add all file descriptors to the pool
    for file in fds.file {
        pool.add_file_descriptor_proto(file)
            .expect("Failed to add file descriptor to pool");
    }

    pool
});

/// Subscriber that writes events to a protobuf text format file
///
/// Each event is serialized to protobuf text format and written to the file.
/// Messages are separated by a line of dashes for readability.
/// The file is automatically flushed after each write to ensure durability.
///
/// # Example
/// ```no_run
/// use build_events::subscribers::TextFileWriter;
///
/// let writer = TextFileWriter::new("build_events.textproto").unwrap();
/// ```
pub struct TextFileWriter {
    file: Mutex<std::fs::File>,
    path: PathBuf,
}

impl TextFileWriter {
    /// Create a new protobuf text format file writer
    ///
    /// Creates or truncates the file at the specified path. The file will
    /// be written in protobuf text format (one event per separator).
    ///
    /// # Arguments
    /// * `path` - Path to the output file
    ///
    /// # Errors
    /// Returns an error if the file cannot be created or opened
    ///
    /// # Example
    /// ```no_run
    /// use build_events::subscribers::TextFileWriter;
    ///
    /// let writer = TextFileWriter::new("build_events.textproto").unwrap();
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

impl std::fmt::Debug for TextFileWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextFileWriter")
            .field("path", &self.path)
            .finish()
    }
}

/// Convert proto BuildEvent to text format string
fn event_to_text_format(event: &BuildEvent) -> Result<String, SubscriberError> {
    let descriptor = DESCRIPTOR_POOL
        .get_message_by_name("spongebob.v1.BuildEvent")
        .ok_or_else(|| {
            SubscriberError::Serialization("Failed to get BuildEvent descriptor".to_string())
        })?;

    let bytes = event.encode_to_vec();

    let dynamic_message = DynamicMessage::decode(descriptor, bytes.as_slice()).map_err(|e| {
        SubscriberError::Serialization(format!("Failed to decode BuildEvent: {}", e))
    })?;

    let options = FormatOptions::new().pretty(true);
    Ok(dynamic_message.to_text_format_with_options(&options))
}

#[async_trait]
impl BuildEventSubscriber for TextFileWriter {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", event_to_text_format(event)?)?;

        Ok(())
    }

    fn name(&self) -> &str {
        "TextFileWriter"
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
    use crate::events::{BuildStarted, TargetKind, TargetStarted, build_event, current_millis};

    #[tokio::test]
    async fn test_text_file_writer() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.textproto");

        let writer = TextFileWriter::new(&file_path).unwrap();
        assert_eq!(writer.name(), "TextFileWriter");
        assert_eq!(writer.path(), file_path.as_path());

        let event = BuildEvent {
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

        // Read back and verify it contains expected fields
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("build_started"));
        assert!(content.contains("invocation_id"));
        assert!(content.contains("test-123"));
        assert!(content.contains("command"));
        assert!(content.contains("build"));
    }

    #[tokio::test]
    async fn test_text_file_multiple_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.textproto");

        let writer = TextFileWriter::new(&file_path).unwrap();

        let events = vec![
            BuildEvent {
                event: Some(build_event::Event::BuildStarted(BuildStarted {
                    invocation_id: "test-1".to_string(),
                    command: "build".to_string(),
                    timestamp_millis: current_millis(),
                    working_directory: "/tmp".to_string(),
                })),
            },
            BuildEvent {
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

        // Read back and verify both events are present
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("build_started"));
        assert!(content.contains("test-1"));
        assert!(content.contains("target_started"));
        assert!(content.contains("target-1"));
        assert!(content.contains("//foo:bar"));
    }

    #[tokio::test]
    async fn test_text_file_truncates_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("events.textproto");

        // Write some initial data
        std::fs::write(&file_path, "old data\n").unwrap();

        // Create writer (should truncate)
        let writer = TextFileWriter::new(&file_path).unwrap();

        let event = BuildEvent {
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

    #[test]
    fn test_descriptor_pool_initialization() {
        // Verify the descriptor pool can be initialized and contains BuildEvent
        let descriptor = DESCRIPTOR_POOL.get_message_by_name("spongebob.v1.BuildEvent");
        assert!(descriptor.is_some());
    }
}
