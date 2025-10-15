//! Build Events Protobuf Layer
//!
//! This crate provides protobuf definitions and SpongeBob client integration for
//! the `build-events` crate. It enables remote observability of builds by sending
//! events to the SpongeBob service via gRPC streaming.
//!
//! # Overview
//!
//! This crate extends the pure Rust `build-events` crate with:
//! - **Protobuf message definitions** for all build event types (via BSR)
//! - **SpongeBob gRPC client** for streaming build events to spongebob.minimal.farm
//! - **BuildEventSubscriber implementation** on SpongeBob for direct integration
//!
//! # Architecture
//!
//! ```text
//! Build Events → BuildEventDispatcher → SpongeBob client → spongebob.minimal.farm
//! ```
//!
//! # Example: Sending Events to SpongeBob
//!
//! ```ignore
//! use build_events::{BuildEventBus, BuildEventDispatcher};
//! use build_events_proto::SpongeBob;
//! use uuid::Uuid;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate invocation ID
//!     let invocation_id = Uuid::new_v4().to_string();
//!
//!     // Create SpongeBob client (opens bidirectional stream)
//!     let spongebob = SpongeBob::new(invocation_id).await?;
//!
//!     // Initialize event bus
//!     let event_bus = BuildEventBus::new(10000);
//!
//!     // Setup dispatcher with SpongeBob as subscriber
//!     let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());
//!     dispatcher.add_subscriber(Box::new(spongebob));
//!
//!     // Start dispatcher in background
//!     tokio::spawn(async move {
//!         dispatcher.run().await;
//!     });
//!
//!     // Events emitted to event_bus are now forwarded to SpongeBob
//!     // ... perform builds ...
//!
//!     Ok(())
//! }
//! ```
//!
//! # Type Usage
//!
//! Since build-events uses proto types directly from BSR, no conversion is needed:
//!
//! ```
//! use build_events::events::{build_event, BuildEvent, BuildStarted, current_millis};
//!
//! // Create proto event (build-events types ARE proto types)
//! let event = BuildEvent {
//!     event: Some(build_event::Event::BuildStarted(BuildStarted {
//!         invocation_id: "invocation-123".to_string(),
//!         command: "build".to_string(),
//!         timestamp_millis: current_millis(),
//!         working_directory: "/tmp".to_string(),
//!     })),
//! };
//! ```

// Use BSR-generated protobuf code from canonical spongebob.v1 package
pub mod proto {
    // Re-export message types from prost
    pub use minimal_spongebob_community_neoeinstein_prost::spongebob::v1::*;

    // Re-export service types from tonic
    pub use minimal_spongebob_community_neoeinstein_tonic::spongebob::v1::tonic::{
        build_event_service_client, build_event_service_server,
    };
}

pub mod client;

// Re-export main types for convenience
pub use client::{Result, SpongeBob, SpongeBobError};
