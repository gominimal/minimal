//! The minimal client's `config.toml`: its schema, the session keys it
//! sets, and the `[secret-store-rules]` with their deny checks.
//!
//! `boxes` re-exports these modules under their old paths. `bep` depends on
//! this crate alone, so the proxy that holds the sealing and CA keys does not
//! link `boxes` or the build-plane crates under it.

pub mod config;
pub mod keys;
pub mod store_rules;
