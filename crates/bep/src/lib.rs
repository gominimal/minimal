//! Box Egress Proxy (BEP): the credential modules a box can be granted, and
//! the sealed envelope that stands in a box for a credential.
//!
//! A box never holds a credential. It holds a sealed value, which only this
//! host's proxy can open, and only for the box, host and module the value was
//! sealed for. The value also carries its host-set version, mode, issue time
//! and expiry. The proxy refuses the value at or after its expiry. It does
//! not compare the other fields with the request. It records the mode for
//! the audit, and admits
//! an authority only when it is in both the carried host-set version's set
//! and the current set. A member sealed under an old host-set version still
//! opens.

pub mod audit;

/// The first line of the message `bep serve` prints when it refuses to
/// start over an audit log line it cannot read (BEP-068). `minvmd` looks
/// for this line in the proxy's log to explain a failed start, so both
/// sides use this one string.
pub const UNREADABLE_AUDIT_LOG_REFUSAL: &str =
    "bep did not start, because its audit log has lines that it cannot read.";
pub mod boxes;
pub mod ca;
pub mod control;
pub mod forward;
pub mod handle;
pub mod http;
pub mod inject;
pub mod keys;
#[cfg(target_os = "linux")]
pub mod linux_store;
pub mod listener;
pub mod module;
pub mod proxy;
pub mod publish;
pub mod redeem;
pub mod redeemer;
pub mod revoke;
pub mod seal;
#[cfg(target_os = "linux")]
pub mod secret_service;
pub mod signin;
pub mod store;
pub mod supervisor;
#[cfg(target_os = "linux")]
pub mod tpm;
pub mod upstream;
