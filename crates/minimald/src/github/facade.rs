//! The in-sandbox mediated-access facade (spec R3): `git%`/`api%` verb
//! dispatch on the session channel.
//!
//! Owned by the `daemon-facade-git` task (git%) and `daemon-facade-api` task
//! (api%). This module will hold the fail-closed argv allowlist for `min
//! git` (push/pull/fetch/remote -v; clone of declared repos only — a
//! security boundary, not a convenience parser) and the fixed operation
//! allowlist for `min api`, both authorizing through `super::authz` before
//! running anything, and reaching GitHub only through
//! `super::state::GithubService`. Access is bound to the sandbox lifetime by
//! construction: this dispatch lives on the same channel actor `env.rs`
//! tears down when the sandbox exits (spec R3.5/R6.3). Every span opened
//! here is `github.facade` (see the span-name conventions documented in
//! `super::state`).
