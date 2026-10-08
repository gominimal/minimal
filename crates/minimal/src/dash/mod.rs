//! `min dash` — an interactive session manager TUI for minimald sessions.
//!
//! Follows an Elm-style architecture: [`app::Model`] is the state,
//! [`app::Msg`] the events, [`app::update`] the pure transition, and
//! [`render::view`] the pure renderer. The tokio driver in [`app::run`]
//! feeds crossterm input and a refresh tick into the loop and executes the
//! returned effects against the daemon connections in [`rpc`].

pub mod app;
pub mod event;
pub mod filter;
pub mod render;
pub mod rpc;
pub mod state;

pub use app::{DashOptions, run};
