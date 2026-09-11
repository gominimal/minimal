//! min-core probe: the `min session attach` sequence over a pluggable
//! transport, built for wasm32-unknown-unknown as well as natively.
//!
//! Scope is Milestone 1 of gominimal/inbox#606: prove that the client side of
//! the attach handshake compiles for the browser on top of russh, with the SSH
//! session terminating in the tab and a dumb WebSocket↔UDS relay in between.
//! Nothing here touches the `minimal` workspace; it is deliberately
//! dependency-minimal so the carve-out cost is visible in `Cargo.lock`.

pub mod attach;
pub mod credential;
pub mod dpop;
pub mod rt;
pub mod wg;
#[cfg(not(target_arch = "wasm32"))]
pub mod stub;
#[cfg(not(target_arch = "wasm32"))]
pub mod testing;
#[cfg(target_arch = "wasm32")]
pub mod web;

pub use attach::{Attach, ConnectOptions, Error, Event, Grid, MINIMAL_SESSION_ID_ENV, Reader, SSH_USER, Writer};
