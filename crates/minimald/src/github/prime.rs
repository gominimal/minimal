//! Repo pre-priming (spec R2): the `GithubPrimeRepos` activation handler.
//!
//! Owned by the `daemon-prime-repos` task. This module will drive, per
//! declared repo, a `github::gitops` clone (temp + rename) or adopt-local
//! wiring, followed by checkout-or-create of the requested branch, using a
//! token obtained through `super::state::GithubService::grants` and
//! authorized via `super::authz`. Every span opened here is `github.prime`
//! (see the span-name conventions documented in `super::state`). A per-repo
//! failure must roll back only that repo's directory and never push
//! implicitly (spec R2.5/R2.6).
