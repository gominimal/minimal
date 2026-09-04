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

use std::collections::{BTreeMap, BTreeSet};

/// Prefix marking a channel env var as one of a task's resolved
/// `env_vars`. Client (`set_env`) and daemon (exec dispatch) both
/// reference this constant — the name cannot skew.
pub const TASK_ENV_PREFIX: &str = "MINIMAL_TASK_ENV_";

/// Channel env var carrying the names the daemon must *remove* from the
/// task's declarations, as a JSON array.
///
/// A resolved value can be sent as itself; a variable the client decided
/// the task must not see cannot. Absence is not a signal — the daemon
/// applies [`TASK_ENV_PREFIX`] entries by insertion, so a name the client
/// simply omits keeps whatever `minimal.toml` declared and is resolved
/// daemon-side. Dropping one therefore has to be said out loud.
///
/// Deliberately **not** under [`TASK_ENV_PREFIX`]: a name that started
/// with it would be stripped by [`from_channel_env`] and delivered to the
/// task as a variable called `DROP`.
pub const TASK_ENV_DROP: &str = "MINIMAL_TASK_DROP";

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

/// Encode the names the daemon must remove from the task's declarations,
/// for [`TASK_ENV_DROP`]. JSON for the same reason argv words travel as
/// JSON in [`crate::exec`]: an env var name is a TOML key and may hold
/// anything, so no separator character is safe to assume.
#[must_use]
pub fn encode_drops(names: &BTreeSet<String>) -> String {
    serde_json_lenient::to_string(names).unwrap_or_else(|_| "[]".to_string())
}

/// The names a client asked the daemon to drop, from a channel's env map.
///
/// Absent, empty, or unparseable yields an empty set — a drop list is an
/// instruction to remove something, and failing to understand one must
/// never remove the wrong thing. An older client sends none, which leaves
/// the task's declarations exactly as `minimal.toml` wrote them.
#[must_use]
pub fn drops_from_channel_env(env_vars: &BTreeMap<String, String>) -> BTreeSet<String> {
    env_vars
        .get(TASK_ENV_DROP)
        .and_then(|raw| serde_json_lenient::from_str(raw).ok())
        .unwrap_or_default()
}

/// A task's `env_vars` as the client resolved them: the values to apply,
/// and the names to remove.
///
/// The two halves are disjoint by construction — a name is either resolved
/// or dropped — and travel together because the daemon needs both to
/// arrive at the set the task actually sees.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskEnv {
    /// Values to apply over the task's own declarations.
    pub set: BTreeMap<String, String>,
    /// Names to remove from the task's declarations entirely.
    pub drop: BTreeSet<String>,
}

impl TaskEnv {
    /// `true` when there is nothing for the daemon to apply — the case for
    /// every caller other than a task run, and for a task declaring no
    /// `env_vars`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.drop.is_empty()
    }
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

    /// The drop list round-trips, and a name on it is not also a value:
    /// the daemon reads the two halves from different channel vars.
    #[test]
    fn drop_list_round_trips() {
        let drops: BTreeSet<String> = ["NOISY_DEBUG".to_string(), "OTHER".to_string()]
            .into_iter()
            .collect();
        let mut channel = BTreeMap::new();
        channel.insert(TASK_ENV_DROP.to_string(), encode_drops(&drops));

        assert_eq!(drops_from_channel_env(&channel), drops);
        // The drop carrier is not itself a task variable.
        assert!(from_channel_env(&channel).is_empty());
    }

    /// `TASK_ENV_DROP` must not live under `TASK_ENV_PREFIX`, or
    /// `from_channel_env` would strip the prefix and hand the task a
    /// variable named `DROP` holding a JSON array.
    #[test]
    fn the_drop_carrier_is_not_under_the_value_prefix() {
        assert!(!TASK_ENV_DROP.starts_with(TASK_ENV_PREFIX));
    }

    /// No drop list, an empty one, and a malformed one all mean "remove
    /// nothing". Failing to parse an instruction to delete must never
    /// delete the wrong thing, and an older client sends none at all.
    #[test]
    fn an_absent_or_unparseable_drop_list_removes_nothing() {
        let mut absent = BTreeMap::new();
        absent.insert("MINIMAL_SESSION_ID".to_string(), "an-id".to_string());
        assert!(drops_from_channel_env(&absent).is_empty());

        let mut empty = BTreeMap::new();
        empty.insert(TASK_ENV_DROP.to_string(), encode_drops(&BTreeSet::new()));
        assert!(drops_from_channel_env(&empty).is_empty());

        let mut junk = BTreeMap::new();
        junk.insert(TASK_ENV_DROP.to_string(), "not json".to_string());
        assert!(drops_from_channel_env(&junk).is_empty());
    }

    /// A name needing no escaping in JSON and one that does both survive,
    /// so a dropped name matches the declaration it must remove exactly.
    #[test]
    fn drop_names_survive_verbatim() {
        let gnarly: BTreeSet<String> = ["PLAIN".to_string(), "with \"quote\" and \\".to_string()]
            .into_iter()
            .collect();
        let mut channel = BTreeMap::new();
        channel.insert(TASK_ENV_DROP.to_string(), encode_drops(&gnarly));
        assert_eq!(drops_from_channel_env(&channel), gnarly);
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
