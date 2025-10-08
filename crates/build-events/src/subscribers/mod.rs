//! Built-in subscriber implementations
//!
//! This module provides ready-to-use subscriber implementations:
//! - [`LoggerSubscriber`]: Logs events using tracing
//! - [`JsonFileWriter`]: Writes events to a JSON-lines file

mod json_file;
mod logger;

pub use json_file::JsonFileWriter;
pub use logger::LoggerSubscriber;
