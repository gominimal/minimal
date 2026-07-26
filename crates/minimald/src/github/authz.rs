//! The GitHub authorization choke point (spec R5.4).
//!
//! Owned by the `daemon-authz` task. This module will hold the typed
//! `Record.attrs` read/write helpers for a session's bound grant, declared
//! repo allow-list, and resolved scopes, plus the single
//! `authorize(&Record, repo, permission)` function every authenticated
//! GitHub operation (`prime`, `push_pr`, `facade`) must call before touching
//! the network: grant bound AND repo in the session's declared allow-list
//! AND permission in the resolved scope set. Callers must hold a live-session
//! handle, so a destroyed session authorizes nothing.
