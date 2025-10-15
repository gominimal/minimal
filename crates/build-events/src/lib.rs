//! Build Events System
//!
//! A dedicated build event protocol (BEP) system that enables remote observability
//! of build execution. This system is separate from diagnostic tracing and emits
//! structured, strongly-typed events that can be consumed by local and remote services.
//!
//! # Overview
//!
//! The build-events crate provides:
//! - **Strongly-typed event definitions** as pure Rust enums and structs
//! - **BuildEventBus** for publishing events using tokio broadcast channels
//! - **BuildEventSubscriber** trait for consuming events
//! - **BuildEventDispatcher** for managing multiple subscribers
//! - **Built-in subscribers** for logging and JSON file output
//!
//! # Architecture
//!
//! ```text
//! Build Components → BuildEventBus → BuildEventDispatcher → Subscribers
//!                                                            ├─ LoggerSubscriber
//!                                                            ├─ JsonFileWriter
//!                                                            └─ Custom Subscribers
//! ```
//!
//! # Example
//!
//! ```no_run
//! use build_events::{
//!     BuildEventBus, BuildEventDispatcher, BuildEvent,
//!     events::{build_event, BuildStarted, current_millis},
//!     subscribers::{LoggerSubscriber, JsonFileWriter},
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize tracing for LoggerSubscriber
//!     tracing_subscriber::fmt::init();
//!
//!     // Create event bus
//!     let event_bus = BuildEventBus::new(10000);
//!
//!     // Setup subscribers
//!     let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());
//!     dispatcher.add_subscriber(Box::new(LoggerSubscriber::new()));
//!     dispatcher.add_subscriber(Box::new(
//!         JsonFileWriter::new("build_events.jsonl").unwrap()
//!     ));
//!
//!     // Start event processing
//!     let dispatcher_handle = tokio::spawn(async move {
//!         dispatcher.run().await
//!     });
//!
//!     // Emit events from build
//!     event_bus.emit(BuildEvent {
//!         invocation_id: "build-123".to_string(),
//!         event: Some(build_event::Event::BuildStarted(BuildStarted {
//!             invocation_id: "build-123".to_string(),
//!             command: "cargo build".to_string(),
//!             timestamp_millis: current_millis(),
//!             working_directory: std::env::current_dir()
//!                 .unwrap()
//!                 .to_string_lossy()
//!                 .to_string(),
//!         })),
//!     });
//!
//!     // ... perform build ...
//!
//!     // Shutdown: drop event_bus, wait for dispatcher to drain
//!     drop(event_bus);
//!     let _ = dispatcher_handle.await;
//! }
//! ```
//!
//! # Event Types
//!
//! The system includes 6 core event types:
//! - [`BuildStarted`](events::BuildStarted) / [`BuildFinished`](events::BuildFinished)
//! - [`TargetStarted`](events::TargetStarted) / [`TargetCompleted`](events::TargetCompleted)
//! - [`ActionStarted`](events::ActionStarted) / [`ActionCompleted`](events::ActionCompleted)
//!
//! All events are strongly-typed Rust structs with `Clone`, `Debug`, `Serialize`,
//! and `Deserialize` implementations.
//!
//! # Custom Subscribers
//!
//! You can implement custom subscribers by implementing the
//! [`BuildEventSubscriber`] trait:
//!
//! ```
//! use build_events::{BuildEvent, BuildEventSubscriber, SubscriberError};
//! use async_trait::async_trait;
//!
//! struct MySubscriber;
//!
//! #[async_trait]
//! impl BuildEventSubscriber for MySubscriber {
//!     async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError> {
//!         // Handle event (serialize to protobuf, send over network, etc.)
//!         println!("Event: {:?}", event);
//!         Ok(())
//!     }
//!
//!     fn name(&self) -> &str {
//!         "MySubscriber"
//!     }
//! }
//! ```
//!
//! # Error Handling
//!
//! - **Bus emission**: Best-effort, never blocks. Slow subscribers may lag and miss events.
//! - **Subscriber errors**: Logged via `tracing::warn!`, but don't stop other subscribers.
//! - **Backpressure**: Broadcast channel size is configurable; slow subscribers will lag.

pub mod bus;
pub mod dispatcher;
pub mod events;
pub mod subscriber;
pub mod subscribers;

// Re-export main types for convenience
pub use bus::BuildEventBus;
pub use dispatcher::BuildEventDispatcher;
pub use events::BuildEvent;
pub use subscriber::{BuildEventSubscriber, SubscriberError};

// Global event bus infrastructure
use std::sync::OnceLock;

static GLOBAL_EVENT_BUS: OnceLock<BuildEventBus> = OnceLock::new();

/// Initialize the global event bus
///
/// This should be called once at application startup before any events are emitted.
/// Panics if called more than once.
pub fn initialize_global_event_bus() {
    GLOBAL_EVENT_BUS
        .set(BuildEventBus::new(10000))
        .expect("Global event bus already initialized");
}

/// Get a reference to the global event bus
///
/// Panics if the global event bus has not been initialized via `initialize_global_event_bus`.
pub fn event_bus() -> &'static BuildEventBus {
    GLOBAL_EVENT_BUS
        .get()
        .expect("Global event bus not initialized. Call initialize_global_event_bus() first.")
}
