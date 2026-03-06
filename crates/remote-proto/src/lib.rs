//! Protobuf / wire types for the Remote Execution Service (RES).
//!

include!(concat!(env!("OUT_DIR"), "/_.rs"));

/// Remote execution service
pub mod res {
    include!(concat!(env!("OUT_DIR"), "/res.rs"));
}
