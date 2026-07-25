//! Facade verb constants shared by the in-sandbox `min` helper script and the
//! daemon dispatch (spec R3).
//!
//! The in-sandbox `min git` / GitHub-MCP facade speaks a small set of verbs back
//! to the daemon over the trusted transport. Defining them here — in the
//! dependency-light types crate both sides already share — keeps the helper
//! script and the daemon's dispatch match arm from drifting apart.

/// Facade verb for git operations (`push`, `pull`, `fetch`, …) proxied to the
/// daemon, which performs the authenticated operation (spec R3.1).
pub const VERB_GIT: &str = "git";

/// Facade verb for GitHub REST API calls (used by GitHub MCP), routed through
/// the daemon so the token stays out of the sandbox (spec R3.3).
pub const VERB_API: &str = "api";

/// All facade verbs, for exhaustive iteration in the dispatch layer.
pub const ALL: [&str; 2] = [VERB_GIT, VERB_API];
