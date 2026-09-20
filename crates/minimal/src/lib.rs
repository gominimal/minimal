//! The minimal CLI which pairs/talks-with minimald.

mod attach;
pub mod auth;
pub mod autospawn;
// The SSH client transport lives in the shared `minimal-client` crate (used
// by the TUI as well); re-exported here so internal `crate::client::...`
// paths and downstream users of `minimal::client` keep working.
pub use minimal_client as client;
pub mod completion;
pub mod completions;
pub mod config;
pub mod diag;
pub mod dirs;
pub mod git_remote;
pub mod loadouts;
pub mod prompt;
pub mod task;
pub mod theme;
pub mod zed;

mod cli;
pub use cli::*;

pub(crate) use minimal_client::file_upload;

pub(crate) mod cmd;
pub use cmd::*;

#[cfg(test)]
mod tests;
