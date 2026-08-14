//! The credential lane: a host-side broker that holds outbound credentials and
//! injects them on the way out, so a box never holds plaintext.
//!
//! A box is handed an unauthenticated per-lane URL and a session-scoped bearer
//! token. It calls the broker; the broker authenticates the token, resolves the
//! lane against its own table, injects the credential into the outbound request,
//! and proxies to the upstream the *user* bound — never one the project or the
//! box named.
//!
//! The broker runs wherever gvproxy runs, because the switch NATs its host alias
//! to that machine's loopback: `minvmd` owns it on the microVM platforms,
//! `minimald` owns it on native Linux. See
//! `docs/specs/12-spec-credential-lane/12-spec-credential-lane.md`.

pub mod endpoint;
pub mod lane;
pub mod proxy;
pub mod token;

pub use endpoint::{BoxLocation, BrokerEndpoint};
pub use lane::{Inject, Lane, Secret};
pub use proxy::{Connector, LaneTable, TOKEN_HEADER, TlsUpstream};
pub use token::{Refused, RegistrationHandle, Token, TokenStore};
