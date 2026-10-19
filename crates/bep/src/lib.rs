//! Box Egress Proxy (BEP): the credential modules a box can be granted, and
//! the sealed envelope that stands in a box for a credential.
//!
//! A box never holds a credential. It holds a sealed value, which only this
//! host's proxy can open, and only for the box, host, module, host-set
//! version, mode and expiry the value was sealed for.

pub mod module;
pub mod seal;
