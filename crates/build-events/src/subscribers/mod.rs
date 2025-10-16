//! Built-in subscriber implementations
//!
//! This module provides ready-to-use subscriber implementations:
//! - [`LoggerSubscriber`]: Logs events using tracing
//! - [`TextFileWriter`]: Writes events to a protobuf text format file

mod logger;
mod text_file;

pub use logger::LoggerSubscriber;
pub use text_file::TextFileWriter;
