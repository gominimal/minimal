//! GitHub integration for `minimald` sessions (spec 10).
//!
//! This module tree is the daemon-side half of spec 10: `minimald` is the
//! GitHub App's OAuth client, holds the resulting tokens, and mediates every
//! GitHub-touching operation a session performs so that a token never enters
//! the sandbox (see the PRD's "Security model" section).
//!
//! [`state::GithubService`] is the composition root — one shared instance,
//! constructed at daemon startup and hung off `ServerStateHandle` (see
//! `crate::server`) — that every other submodule here is built to consume.
//! The submodules are pre-registered as an explicit fan-out target: each
//! owns one disjoint file, so the daemon tasks that implement them
//! (`daemon-auth-rpcs`, `daemon-authz`, `daemon-prime-repos`,
//! `daemon-push-pr`, `daemon-facade-git`) can land in parallel without
//! touching each other's files.
//!
//! - [`rpcs`] — the `GithubBeginLogin`/`GithubPollLogin`/`GithubStatus`/
//!   `GithubListAuths`/`GithubLogout` oneshot RPC handlers (spec R1.1–R1.4).
//! - [`authz`] — the single `authorize(&Record, repo, permission)` choke
//!   point every authenticated op must pass through (spec R5.4).
//! - [`prime`] — the `GithubPrimeRepos` activation handler: clone/adopt +
//!   checkout-or-create (spec R2).
//! - [`push_pr`] — `GithubPush`/`GithubCreatePr`/`GetSessionGitState` (spec
//!   R3.4, R4).
//! - [`facade`] — the in-sandbox `min git`/`min api` verb dispatch (spec R3).

pub mod authz;
pub mod facade;
pub mod prime;
pub mod push_pr;
pub mod rpcs;
pub mod state;

pub use state::GithubService;
