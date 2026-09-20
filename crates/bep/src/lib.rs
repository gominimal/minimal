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
//! - [`redeem`] is the redemption decision: one pure function that admits a
//!   request carrying a sealed value exactly when every check passes, and
//!   names the first failing check otherwise.
//! - [`ca`] is the interception certificates: the root a box trusts, the one
//!   signing certificate constrained to the names the host's boxes declare,
//!   and the leaves issued under it.
//! - [`audit`] is the log: one hash-chained JSONL record per decision, append
//!   only, carrying no credential and no body.
//! - [`control`] is the control socket's audit submissions: how a client's
//!   mints and revocations reach the log the proxy alone writes.
//! - [`github`] is the GitHub sign-in: the device and browser flows under
//!   the Minimal-published App, and the host store the sign-in lives in.
//! - [`mint`] mints a member from the held sign-in, sealed to this host,
//!   and makes the identity events a mint and a logout record.
//! - [`listener`] is the shell around the decision: it accepts a box's
//!   connections, terminates TLS for the declared hosts, decides each request
//!   and forwards it with the substitution the decision allows.
//! - [`upstream`] is the upstream leg of a terminated flow, validated against
//!   the host's trust store before anything is forwarded on it.

pub mod audit;
pub mod ca;
pub mod control;
pub mod github;
pub mod keychain;
pub mod keys;
pub mod listener;
pub mod mint;
pub mod redeem;
pub mod seal;
pub mod upstream;

// `Decision` stays module-qualified on both sides: the audit log's admit or
// refuse is not the redemption outcome.
pub use audit::{AuditError, Event, Hash, Kind, Log, Mapping, Record};
pub use ca::{Authority, CaError, DeclaredUnion, Leaf};
pub use control::{ControlError, Submission, submit};
pub use github::{GitHub, GitHubError, MemorySignIns, SignIn, SignInStore};
pub use keychain::{KeyStore, MemoryStore, PrivateKey, StoreError};
pub use keys::{Fingerprint, KeyRole, KeyStatus, Keys, KeysError, inspect};
pub use listener::{Addressing, Attachments, Config, ListenerError, Module, Proxy, Sender};
pub use mint::{MintError, MintRequest, Minted, mint, revocation_event};
pub use redeem::{Check, Decision, Redemption, decide};
pub use seal::{Member, Refusal, SealError, SealedContext, SealedValue, Unsealed, seal, unseal};
pub use upstream::{Resolver, Trust, TrustError, UpstreamError, Validated};
