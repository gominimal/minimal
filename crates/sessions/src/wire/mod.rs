//! Wire-form types for client/daemon RPC.
//!
//! These types mirror the local domain types in [`crate::core`] but
//! are kept entirely separate so the wire schema can evolve
//! independently of the TOML loadout schema and other local forms.
//! All types here are JSON-friendly: enums use an explicit `kind`
//! tag, newtypes are `#[serde(transparent)]`, and rich error sources
//! collapse at the boundary (see [`errors`]).

pub mod errors;
pub mod policy;
pub mod primitives;
pub mod request;
