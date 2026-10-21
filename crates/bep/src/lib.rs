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
pub mod ca;
pub mod control;
pub mod forward;
pub mod handle;
pub mod http;
pub mod keys;
pub mod listener;
pub mod module;
pub mod proxy;
pub mod publish;
pub mod redeem;
pub mod seal;
pub mod signin;
pub mod upstream;
