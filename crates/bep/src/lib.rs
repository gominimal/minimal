//! Box Egress Proxy (BEP): the credential modules a box can be granted, and
//! the sealed envelope that stands in a box for a credential.
//!
//! A box never holds a credential. It holds a sealed value, which only this
//! host's proxy can open, and only for the box, host and module the value was
//! sealed for. The value also carries its host-set version, mode and expiry,
//! and a change to any of them makes it fail to open.

pub mod module;
pub mod seal;
