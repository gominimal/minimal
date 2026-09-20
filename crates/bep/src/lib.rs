//! The Box Egress Proxy's credential custody: keys held non-exportable in the
//! host key store, and the sealed envelope that binds a minted member to this
//! host's key and to its authenticated context.
//!
//! - [`keychain`] is the store seam: what a private key can do, and the
//!   backends that hold one (the macOS Keychain, and an in-process store for
//!   tests and for hosts with no bound store yet).
//! - [`keys`] is the proxy's key set: the sealing key, the root CA key and
//!   the signing CA key, generated once and replaced only on an operator
//!   command.
//! - [`mod@seal`] is the envelope: seal a member to this host, unseal it under
//!   this host's key alone.

pub mod keychain;
pub mod keys;
pub mod seal;

pub use keychain::{KeyStore, MemoryStore, PrivateKey, StoreError};
pub use keys::{Fingerprint, KeyRole, KeyStatus, Keys, KeysError, inspect};
pub use seal::{Member, Refusal, SealError, SealedContext, SealedValue, Unsealed, seal, unseal};
