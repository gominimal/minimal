//! GitHub auth RPC handlers (spec R1.1–R1.4): `GithubBeginLogin`,
//! `GithubPollLogin`, `GithubStatus`, `GithubListAuths`, `GithubLogout`.
//!
//! Owned by the `daemon-auth-rpcs` task. Handlers here delegate to
//! `super::state::GithubService`'s device-flow client and `GrantManager`
//! (device-flow login/poll, status, logout), plus refresh status reporting;
//! every span opened here is `github.auth` or `github.refresh` (see the
//! span-name conventions documented in `super::state`). No handler may
//! return a response type carrying token material — every RPC response type
//! is defined in `minimald-rpc` as plain, token-free data.
