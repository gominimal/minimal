//! Resolved task environment, propagated CLI → daemon over the SSH channel
//! environment.
//!
//! Part of the wire contract: `min task run` resolves a task's
//! `env_vars.X = { inherit = true }` entries against the *invoking shell*
//! and sends each as a channel `env` request under [`TASK_ENV_PREFIX`] —
//! the same mechanism as `MINIMAL_SESSION_ID` and
//! [`TRACEPARENT`](crate::trace::TRACEPARENT_ENV) — and the daemon strips
//! the prefix and applies the values verbatim instead of resolving
//! `inherit` against its own environment.
//!
//! Resolution has to happen client-side because the daemon is a different
//! process, usually on the far side of a VM boundary: its `std::env::var`
//! reads the daemon's environment, which the user's `export` never reaches.
//! That asymmetry is the whole of gominimal/inbox#585 — `[session.vars]`
//! already resolved client-side at activation and worked, while a task's
//! `env_vars` resolved daemon-side and could not.
//!
//! The prefix carries the variable's name and the SSH env request carries
//! its value, both verbatim, so nothing is escaped and any string a shell
//! can export round-trips exactly.

use std::collections::BTreeMap;

/// Prefix marking a channel env var as one of a task's resolved
/// `env_vars`. Client (`set_env`) and daemon (exec dispatch) both
/// reference this constant — the name cannot skew.
pub const TASK_ENV_PREFIX: &str = "MINIMAL_TASK_ENV_";

/// The channel env var name carrying task variable `name`.
#[must_use]
pub fn wire_name(name: &str) -> String {
    format!("{TASK_ENV_PREFIX}{name}")
}

/// Extract a task's resolved env vars from a channel's env map, stripping
/// [`TASK_ENV_PREFIX`] from each name.
///
/// Entries without the prefix — `MINIMAL_SESSION_ID`, `TRACEPARENT`,
/// anything else a client sent — are ignored rather than rejected. A client
/// that sends none yields an empty map, which is exactly the pre-#585
/// behaviour: the daemon falls back to resolving `inherit` itself, so an
/// older client against a newer daemon is no worse off than before.
#[must_use]
pub fn from_channel_env(env_vars: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    env_vars
        .iter()
        .filter_map(|(k, v)| Some((k.strip_prefix(TASK_ENV_PREFIX)?.to_string(), v.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name survives the prefix round-trip, which is the whole contract:
    /// the client prefixes, the daemon strips, and the task sees the name
    /// its `minimal.toml` declared.
    #[test]
    fn wire_name_round_trips_through_from_channel_env() {
        let mut channel = BTreeMap::new();
        channel.insert(wire_name("ZZ_TASK_TOKEN"), "task-value-123".to_string());

        let out = from_channel_env(&channel);
        assert_eq!(
            out.get("ZZ_TASK_TOKEN").map(String::as_str),
            Some("task-value-123")
        );
        assert_eq!(out.len(), 1);
    }

    /// The channel also carries `MINIMAL_SESSION_ID` and `TRACEPARENT`;
    /// neither is a task variable and neither may leak into the task's
    /// environment.
    #[test]
    fn unprefixed_channel_vars_are_ignored() {
        let mut channel = BTreeMap::new();
        channel.insert("MINIMAL_SESSION_ID".to_string(), "an-id".to_string());
        channel.insert(
            crate::trace::TRACEPARENT_ENV.to_string(),
            "00-aa-bb-01".to_string(),
        );
        channel.insert(wire_name("KEPT"), "yes".to_string());

        let out = from_channel_env(&channel);
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("KEPT"));
    }

    /// A client that sends no task env yields an empty map — the signal
    /// the daemon reads as "resolve `inherit` yourself", preserving the
    /// behaviour of a client that predates this field.
    #[test]
    fn absent_task_env_is_empty_not_an_error() {
        let mut channel = BTreeMap::new();
        channel.insert("MINIMAL_SESSION_ID".to_string(), "an-id".to_string());
        assert!(from_channel_env(&channel).is_empty());
    }

    /// Values are carried verbatim: no escaping is applied on either side,
    /// so a value holding newlines, `=`, quotes, or non-ASCII arrives
    /// exactly as the shell exported it. A variable whose own name starts
    /// with the prefix round-trips too, since only one prefix is stripped.
    #[test]
    fn values_and_prefixed_names_survive_verbatim() {
        let gnarly = "line1\nline2 = \"quoted\" — ünicode\t\\";
        let mut channel = BTreeMap::new();
        channel.insert(wire_name("GNARLY"), gnarly.to_string());
        channel.insert(wire_name("MINIMAL_TASK_ENV_X"), "inner".to_string());

        let out = from_channel_env(&channel);
        assert_eq!(out.get("GNARLY").map(String::as_str), Some(gnarly));
        assert_eq!(
            out.get("MINIMAL_TASK_ENV_X").map(String::as_str),
            Some("inner")
        );
    }

    /// An empty value is a real value, not an absence: `export X=` must
    /// reach the task as an empty string rather than being dropped.
    #[test]
    fn empty_values_are_carried() {
        let mut channel = BTreeMap::new();
        channel.insert(wire_name("EMPTY"), String::new());

        let out = from_channel_env(&channel);
        assert_eq!(out.get("EMPTY").map(String::as_str), Some(""));
    }
}
