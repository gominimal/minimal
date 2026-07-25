//! Pure domain types for GitHub-integrated `minimald` sessions (spec 10).
//!
//! This crate's default feature set keeps clear of any HTTP stack: it holds the
//! parsed value types, the typed permission model, the secret newtype, the
//! daemon configuration, the session-`attrs` codec, the on-disk grant store,
//! and the error taxonomy that both `minimald` and the `min` client agree on.
//! Local filesystem I/O for the grant store (`serde`, `serde_json`, `chrono`)
//! is part of the default build; no network I/O, and no reqwest, is pulled in
//! until the future `client` feature lands. Keeping the dependency set light
//! lets `mfile` and `minimal` depend on this crate cheaply.
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
pub mod store;
pub mod types;

// A programmable, in-process mock GitHub (OAuth device flow + REST + an
// auth-enforcing git smart-HTTP endpoint) plus the `github-mock` binary. It is
// test-only scaffolding — never a production dependency — so it is gated behind
// the `test-support` feature and carries no weight in the default build.
#[cfg(feature = "test-support")]
pub mod testing;

pub use config::GithubConfig;
pub use error::Error;
pub use scopes::{Permission, Scope, ScopeSet};
pub use secret::SecretString;
pub use store::{Grant, GrantState, GrantStore, GrantSummary};
pub use types::{AuthChoice, BranchSpec, GrantId, RepoSpec};
