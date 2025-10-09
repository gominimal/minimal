//! Build Events Protobuf Layer
//!
//! This crate provides protobuf definitions and gRPC streaming support for
//! the `build-events` crate. It enables remote observability of builds via
//! gRPC streaming.
//!
//! # Overview
//!
//! This crate extends the pure Rust `build-events` crate with:
//! - **Protobuf message definitions** for all build event types
//! - **Type conversions** between Rust and protobuf types
//! - **GrpcStreamSubscriber** for converting events to proto and streaming
//! - **BuildEventService** gRPC service implementation
//!
//! # Architecture
//!
//! ```text
//! Build Events (Rust) → Conversion → Proto Events → gRPC Stream → Clients
//! ```
//!
//! # Example: gRPC Streaming
//!
//! ## Server Side
//!
//! ```no_run
//! use build_events::{BuildEventBus, BuildEventDispatcher};
//! use build_events_proto::{
//!     GrpcStreamSubscriber,
//!     BuildEventServiceImpl,
//!     proto::build_event_service_server::BuildEventServiceServer,
//! };
//! use tonic::transport::Server;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create event bus
//!     let event_bus = BuildEventBus::new(10000);
//!
//!     // Create gRPC service
//!     let service = BuildEventServiceImpl::new(1000);
//!     let sender = service.sender();
//!
//!     // Setup dispatcher with a subscriber that feeds the gRPC service
//!     let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());
//!     let subscriber = GrpcStreamSubscriber::new(100);
//!     dispatcher.add_subscriber(Box::new(subscriber));
//!
//!     // Start dispatcher
//!     tokio::spawn(async move {
//!         dispatcher.run().await;
//!     });
//!
//!     // Start gRPC server
//!     Server::builder()
//!         .add_service(BuildEventServiceServer::new(service))
//!         .serve("[::1]:50051".parse()?)
//!         .await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Client Side
//!
//! ```no_run
//! use build_events_proto::proto::{
//!     build_event_service_client::BuildEventServiceClient,
//!     StreamEventsRequest,
//! };
//! use tokio_stream::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = BuildEventServiceClient::connect("http://[::1]:50051").await?;
//!
//!     let request = StreamEventsRequest {
//!         invocation_id: None,
//!         start_timestamp_millis: None,
//!     };
//!
//!     let mut stream = client.stream_events(request).await?.into_inner();
//!
//!     while let Some(event) = stream.next().await {
//!         let event = event?;
//!         println!("Received event: {:?}", event);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Type Conversions
//!
//! Convert between Rust and protobuf types:
//!
//! ```
//! use build_events::events::{BuildStarted, current_millis};
//! use build_events::BuildEvent;
//! use build_events_proto::proto;
//!
//! // Rust -> Proto
//! let rust_event = BuildEvent::BuildStarted(BuildStarted {
//!     invocation_id: "test-123".to_string(),
//!     command: "build".to_string(),
//!     timestamp_millis: current_millis(),
//!     working_directory: "/tmp".to_string(),
//! });
//!
//! let proto_event: proto::BuildEvent = rust_event.clone().into();
//!
//! // Proto -> Rust
//! let converted_back: BuildEvent = proto_event.try_into().unwrap();
//! assert_eq!(rust_event, converted_back);
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

pub mod convert;
pub mod service;
pub mod subscriber;

#[cfg(feature = "spongebob-subscriber")]
pub mod spongebob_subscriber_v2;

// Re-export main types for convenience
pub use convert::{ConversionError, ToProto, to_proto_build_event};
pub use service::BuildEventServiceImpl;
pub use subscriber::GrpcStreamSubscriber;

#[cfg(feature = "spongebob-subscriber")]
pub use spongebob_subscriber_v2::SpongeBobSubscriberV2;
