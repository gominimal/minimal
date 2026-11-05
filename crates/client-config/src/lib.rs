//! The minimal client's `config.toml`: its schema, the session keys it
//! sets, the `[secret-store-rules]` with their deny checks, and the
//! `[host-exposures]` table.
//!
//! `boxes` re-exports these modules under their old paths. `bep` depends on
//! this crate alone, so the proxy that holds the sealing and CA keys does not
//! link `boxes` or the build-plane crates under it.

pub mod config;
pub mod host_exposures;
pub mod keys;
pub mod store_rules;
