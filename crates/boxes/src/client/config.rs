//! The client configuration, `<config>/minimal/config.toml`. It lives in the
//! `client-config` crate so `bep` reads it without linking this crate. This
//! path stays for every caller.

pub use client_config::config::*;
