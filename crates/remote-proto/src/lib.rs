//! Protobuf / wire types for the Remote Execution Service (RES).
//!

include!(concat!(env!("OUT_DIR"), "/_.rs"));

/// Remote execution service
// tonic's generated server trait goes through `#[async_trait]`, whose
// expansion puts `#[must_use]` on functions that already return a pinned
// boxed future; clippy 1.99 reports that as `double_must_use` on the
// included source. Generated code: nothing here to change.
#[expect(
    clippy::double_must_use,
    reason = "async_trait expansion in tonic-generated code (tonic-prost-build 0.14)"
)]
pub mod res {
    include!(concat!(env!("OUT_DIR"), "/res.rs"));
}
