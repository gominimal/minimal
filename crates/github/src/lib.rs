//! Pure domain types for GitHub-integrated `minimald` sessions (spec 10).
//!
//! This crate is deliberately I/O-free at its default feature set: it holds the
//! parsed value types, the typed permission model, the secret newtype, the
//! daemon configuration, the session-`attrs` codec, and the error taxonomy that
//! both `minimald` and the `min` client agree on. Keeping it dependency-light
//! (`thiserror`, `url`, `zeroize`) lets `mfile` and `minimal` depend on it
//! cheaply without pulling an HTTP stack.
//!
//! The device-flow + GitHub API client lands later behind a `client` feature
//! (see `Cargo.toml`); code here is structured so that module can be added
//! without reshaping the public surface below.
//!
//! # Security posture
//!
//! Per the spec's load-bearing decision, a GitHub token lives only in the
//! daemon and never enters a sandbox. Two rules this crate enforces mechanically:
//!
//! * The only carrier for token material is [`SecretString`], which redacts in
//!   `Debug`/`Display` and zeroizes on drop and has no `serde` derive. A bare
//!   `String` holding a token is therefore a review-rejectable pattern.
//! * The `workflows` GitHub permission is unrepresentable: [`Scope`] has no such
//!   variant, so no code path can request it (spec NG6).

pub mod attrs;
pub mod config;
pub mod error;
pub mod facade;
pub mod scopes;
pub mod secret;
pub mod types;

pub use config::GithubConfig;
pub use error::Error;
pub use scopes::{Permission, Scope, ScopeSet};
pub use secret::SecretString;
pub use types::{AuthChoice, BranchSpec, GrantId, RepoSpec};
