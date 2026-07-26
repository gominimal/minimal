//! Explicit push and pull-request handling (spec R3.4, R4): `GithubPush`,
//! `GithubCreatePr`, `GetSessionGitState`.
//!
//! Owned by the `daemon-push-pr` task. This module will implement the
//! explicit (never automatic) push RPC, existing-PR detection before
//! creating a new one, PR-template body pickup, and the per-repo git-state
//! query the client-driven PR-on-exit prompt reads. Pushes and PR creates run
//! through `super::authz::authorize` and a token from
//! `super::state::GithubService::grants`; spans opened here are
//! `github.push`/`github.pr` (see the span-name conventions documented in
//! `super::state`).
