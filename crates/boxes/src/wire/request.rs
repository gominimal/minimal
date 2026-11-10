//! Wire-form request / response envelopes for client/daemon RPC.
//!
//! Flow:
//!
//! 1. Client → daemon: [`WireContribution`] composed from the user's
//!    loadouts, shipped inside `CreateSessionRequest` in `minimald-rpc`.
//! 2. Daemon → client: a [`ContributionResponse`] with the
//!    package- and project-sourced items that need client-side
//!    policy gating.
//! 3. Client → daemon: [`ContributionVerdict`] with per-item decisions.

use super::errors::WireError;
use super::policy::{WireHookVerdict, WirePatchVerdict, WireVarVerdict};
use super::primitives::{
    WireOrientation, WirePackageRef, WirePendingHook, WirePendingPatch, WirePendingVar,
    WireProvenancedHook, WireSessionPatch, WireSessionVar,
};
use crate::SessionId;
use crate::core::lifecyclehook::LifecycleHook;
use crate::core::primitives::{LenientVarEntry, Patches, StrictVarName, VarValue};
use std::collections::BTreeMap;

/// Snapshot format version for [`WireComposition`]. Bumped when the
/// on-disk shape changes in a way older daemons can't tolerate.
///
/// - **1** — lifecycle hooks carried `on_failure` and no `description`
///   or per-script `timeout`.
/// - **2** — hooks carry `description`, `on_attach`, `on_detach`, and a
///   per-script `timeout_secs`; `on_failure` is gone.
pub const COMPOSITION_SNAPSHOT_VERSION: u32 = 2;

/// Version assumed for a sidecar with no `version` field. Those were
/// written before the field existed, which is by definition version 1 —
/// so this must not track [`COMPOSITION_SNAPSHOT_VERSION`].
const LEGACY_COMPOSITION_SNAPSHOT_VERSION: u32 = 1;

/// The client's composed contribution, wire-shaped: var values
/// resolved, patch sources expanded to concrete files, every item
/// already gated by the user policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireContribution {
    /// Variables that passed the user policy gate.
    pub vars: Vec<WireSessionVar>,
    /// Patch files that passed the user policy gate.
    pub patches: Vec<WireSessionPatch>,
    /// Lifecycle hooks (no policy applies).
    pub lifecycle_hooks: Vec<WireProvenancedHook>,
    /// Packages the client requested be brought in.
    pub requested_packages: Vec<WirePackageRef>,
    /// First-prompt orientation facts (no policy applies — control
    /// plane, not user vars). Serde-defaulted so payloads from clients
    /// that predate the field deserialize cleanly.
    #[serde(default)]
    pub orientation: WireOrientation,
    /// The `minimal.toml` entry the box comes from, expanded by the client
    /// over `[defaults]`, `[defaults.<type>]` and the entry's own table
    /// (BOX-064). The daemon composes the project's part of the box from
    /// it (BOX-068). `None` from a client that sends no entry: the daemon
    /// then composes from the project's `[session]` table alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<Box<WireBoxEntry>>,
}

/// An expanded `minimal.toml` entry, as the client sends it with its
/// contribution: the lists of the expanded spec that the daemon composes.
///
/// Each list is `None` when the client sends no such list. An absent list
/// leaves the daemon's own project list for that kind of item as it is. A
/// present list, empty or not, is the project's whole list of that kind,
/// except `packages`, which adds to the daemon's (see
/// [`SessionComposer::compose`](crate::daemon::composer::SessionComposer::compose)).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireBoxEntry {
    /// The entry's name: `default`, or the `<name>` of its table.
    pub name: String,
    /// The entry's Box Type, `session` or `task`.
    pub box_type: String,
    /// The project root on the client host. Every item the entry
    /// contributes is the project's, from this directory.
    pub project: paths::HostPath,
    /// `packages`, in expansion order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<String>>,
    /// `vars`, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vars: Option<BTreeMap<StrictVarName, VarValue>>,
    /// `vars_lenient`, in expansion order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vars_lenient: Option<Vec<LenientVarEntry>>,
    /// `patches`, in expansion order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patches: Option<Patches>,
    /// `lifecycle_hooks`, in expansion order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_hooks: Option<Vec<LifecycleHook>>,
}

impl WireBoxEntry {
    /// The entry `name` of `box_type` from `project`, with no lists.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        box_type: impl Into<String>,
        project: paths::HostPath,
    ) -> Self {
        Self {
            name: name.into(),
            box_type: box_type.into(),
            project,
            packages: None,
            vars: None,
            vars_lenient: None,
            patches: None,
            lifecycle_hooks: None,
        }
    }
}

/// Persisted composition snapshot, written by the daemon as a sidecar
/// to [`record.json`](crate::store) at composition-assembly time so a
/// restart can re-apply the exact [`Composition`] that was approved at
/// `min session activate` time.
///
/// Mirrors [`Composition`](crate::core::compose::Composition) via the
/// same wire primitives used for the live RPC flow
/// ([`WireContribution`], [`ContributionResponse`]). A `version` field
/// gates the on-disk shape so a future format can evolve without
/// ambiguity; the current one is [`COMPOSITION_SNAPSHOT_VERSION`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireComposition {
    /// Snapshot format version. Defaults to
    /// [`LEGACY_COMPOSITION_SNAPSHOT_VERSION`] — a sidecar without the
    /// field was written before it existed, which is version 1 by
    /// definition, not whatever the current writer emits.
    #[serde(default = "default_composition_version")]
    pub version: u32,
    /// Variables that survived the policy gate.
    pub vars: Vec<WireSessionVar>,
    /// Patches that survived the policy gate.
    pub patches: Vec<WireSessionPatch>,
    /// Packages contributed to the session (pass-through; no gate).
    pub packages: Vec<WirePackageRef>,
    /// Lifecycle hooks contributed to the session (pass-through; no
    /// gate).
    pub lifecycle_hooks: Vec<WireProvenancedHook>,
    /// First-prompt orientation facts (pass-through; no gate).
    /// Serde-defaulted so sidecars written before the field existed
    /// deserialize cleanly.
    #[serde(default)]
    pub orientation: WireOrientation,
}

fn default_composition_version() -> u32 {
    LEGACY_COMPOSITION_SNAPSHOT_VERSION
}

impl From<&crate::core::compose::Composition> for WireComposition {
    fn from(c: &crate::core::compose::Composition) -> Self {
        Self {
            version: COMPOSITION_SNAPSHOT_VERSION,
            vars: c.vars().iter().cloned().map(Into::into).collect(),
            patches: c.patches().iter().cloned().map(Into::into).collect(),
            packages: c.packages().iter().cloned().map(Into::into).collect(),
            lifecycle_hooks: c
                .lifecycle_hooks()
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
            orientation: c.orientation().clone().into(),
        }
    }
}

/// Daemon → Client: items from the daemon-side closure (packages,
/// project config) that need client-side policy + prompts.
///
/// Sent once per session. After receiving the matching
/// [`ContributionVerdict`] the daemon assembles the session.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContributionResponse {
    /// Session id assigned by the daemon.
    pub session_id: SessionId,
    /// Pending variables awaiting policy + prompt.
    pub vars: Vec<WirePendingVar>,
    /// Pending patches awaiting policy + prompt.
    pub patches: Vec<WirePendingPatch>,
    /// Lifecycle hooks awaiting the hooks-policy gate. Project-declared
    /// hooks only — a loadout's are the user's own and never reach the
    /// daemon-side pending set.
    pub lifecycle_hooks: Vec<WirePendingHook>,
}

/// Client → Daemon: per-item verdicts on the [`ContributionResponse`]'s
/// pending items.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContributionVerdict {
    /// Matches [`ContributionResponse::session_id`].
    pub session_id: SessionId,
    /// One verdict per pending var.
    pub vars: Vec<WireVarVerdict>,
    /// One verdict per pending patch.
    pub patches: Vec<WirePatchVerdict>,
    /// One verdict per pending lifecycle hook. Serde-defaulted so a
    /// verdict from a client that predates the hooks gate deserializes;
    /// the daemon treats a hook with no verdict as refused, so an old
    /// client can never accidentally approve one by omission.
    #[serde(default)]
    pub lifecycle_hooks: Vec<WireHookVerdict>,
}

/// Daemon's reply to a `SubmitVerdict`: composition finalized (the
/// record has moved from `Pending` to
/// [`Materializing`](crate::BoxState::Materializing), not yet
/// `Active`) or a protocol-level fault the transport layer didn't
/// catch.
///
/// The client follows up with a patches upload
/// (`WorkspacePatchesTarZst`) and then `FinalizeSession` to
/// actually promote the record to
/// [`Active`](crate::BoxState::Active). Only after that step
/// is the session attachable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BoxStep {
    /// Composition complete; the session record has been promoted to
    /// [`Materializing`](crate::BoxState::Materializing). The
    /// client must upload the composition's patches and call
    /// `FinalizeSession` before the session is attachable.
    Materialized {
        /// Daemon-assigned session id. Matches the id returned by
        /// the originating `CreateSessionResponse::Pending`.
        id: SessionId,
    },
    /// Protocol-level failure detected by the daemon (unknown
    /// session id, wrong state, or a `resume_from_verdict` failure).
    /// Distinct from a transport error.
    Fault {
        /// Structured fault detail. Nested under a field so its own
        /// `kind` discriminator doesn't collide with this enum's tag.
        error: WireError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::primitives::{PendingId, WireResolvedVar, WireSource, WireVarSpec};

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json_lenient::to_string(value).expect("serialize");
        serde_json_lenient::from_str(&json).expect("deserialize")
    }

    fn session_id() -> SessionId {
        SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    #[test]
    fn empty_contribution_round_trips() {
        let c = WireContribution::default();
        assert_eq!(round_trip(&c), c);
    }

    #[test]
    fn contribution_response_round_trips() {
        let r = ContributionResponse {
            session_id: session_id(),
            vars: vec![WirePendingVar {
                id: PendingId::new(1),
                name: "RUSTC".into(),
                spec: WireVarSpec::Inherit,
                source: WireSource::Package {
                    name: "rust".into(),
                },
                carries_user_data: true,
            }],
            patches: vec![],
            lifecycle_hooks: vec![],
        };
        assert_eq!(round_trip(&r), r);
    }

    #[test]
    fn contribution_verdict_round_trips() {
        let v = ContributionVerdict {
            session_id: session_id(),
            vars: vec![WireVarVerdict::Approved {
                id: PendingId::new(1),
                value: WireResolvedVar {
                    name: "RUSTC".into(),
                    value: "/usr/bin/rustc".into(),
                    carries_user_data: true,
                },
            }],
            patches: vec![WirePatchVerdict::Denied {
                id: PendingId::new(2),
                host_path: paths::HostAbsPath::try_new("/etc/secret").unwrap(),
            }],
            lifecycle_hooks: vec![WireHookVerdict::Approved {
                id: PendingId::new(3),
            }],
        };
        assert_eq!(round_trip(&v), v);
    }

    /// A verdict from a client that predates the hooks gate carries no
    /// `lifecycle_hooks` key at all. It must deserialize to an empty
    /// list — which the daemon treats as "approve nothing" — rather
    /// than failing the message.
    #[test]
    fn contribution_verdict_without_hook_field_deserializes_empty() {
        let json = format!(
            r#"{{"session_id":"{}","vars":[],"patches":[]}}"#,
            session_id()
        );
        let v: ContributionVerdict =
            serde_json_lenient::from_str(&json).expect("legacy verdict must load");
        assert!(
            v.lifecycle_hooks.is_empty(),
            "expected empty, got {:?}",
            v.lifecycle_hooks
        );
    }

    #[test]
    fn session_step_round_trips_all_variants() {
        let materialized = BoxStep::Materialized { id: session_id() };
        let fault = BoxStep::Fault {
            error: WireError::UnknownSessionId,
        };
        assert_eq!(round_trip(&materialized), materialized);
        assert_eq!(round_trip(&fault), fault);
    }

    #[test]
    fn session_step_uses_explicit_kind_tag() {
        let s = BoxStep::Fault {
            error: WireError::UnknownSessionId,
        };
        let json = serde_json_lenient::to_string(&s).unwrap();
        assert!(
            json.contains(r#""kind":"fault""#),
            "expected `kind` tag, got: {json}"
        );
    }

    #[test]
    fn composition_snapshot_round_trips() {
        let c = WireComposition {
            version: 1,
            vars: vec![super::WireSessionVar {
                var: WireResolvedVar {
                    name: "EDITOR".into(),
                    value: "hx".into(),
                    carries_user_data: false,
                },
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            patches: vec![],
            packages: vec![super::WirePackageRef {
                name: "helix".into(),
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            lifecycle_hooks: vec![],
            orientation: WireOrientation {
                loadouts_display: "dev".into(),
            },
        };
        assert_eq!(round_trip(&c), c);
    }

    #[test]
    fn composition_snapshot_defaults_version_to_one() {
        // A sidecar written without the `version` field predates the
        // field, so it is version 1 — not 0, and not whatever the
        // current writer emits.
        let json = r#"{"vars":[],"patches":[],"packages":[],"lifecycle_hooks":[]}"#;
        let c: WireComposition = serde_json_lenient::from_str(json).unwrap();
        assert_eq!(c.version, LEGACY_COMPOSITION_SNAPSHOT_VERSION);
        assert_ne!(c.version, COMPOSITION_SNAPSHOT_VERSION);
    }

    /// A v1 sidecar — `on_failure` present, no `description` or
    /// `timeout_secs` — still loads. Its `on_failure` is dropped and the
    /// remaining scripts take the default timeout.
    #[test]
    fn v1_snapshot_with_on_failure_still_loads() {
        let json = r#"{
            "version": 1,
            "vars": [], "patches": [], "packages": [],
            "lifecycle_hooks": [{
                "hook": {
                    "on_activate": {"kind": "inline", "body": "echo hi"},
                    "on_failure":  {"kind": "inline", "body": "old"}
                },
                "source": {"kind": "user_loadout", "name": "dev"}
            }]
        }"#;
        let c: WireComposition =
            serde_json_lenient::from_str(json).expect("v1 snapshot must still load");
        assert_eq!(c.version, 1);
        let hook = &c.lifecycle_hooks[0].hook;
        assert!(hook.on_activate.is_some());
        assert!(hook.description.is_none());
    }

    /// The writer stamps the current version, so a freshly written
    /// snapshot is distinguishable on read from a legacy one that
    /// omitted the field entirely.
    #[test]
    fn written_snapshot_carries_current_version() {
        let composition =
            crate::core::compose::Composition::from_daemon_passthrough(Vec::new(), Vec::new());
        let wire = WireComposition::from(&composition);
        assert_eq!(wire.version, COMPOSITION_SNAPSHOT_VERSION);
        assert_ne!(wire.version, LEGACY_COMPOSITION_SNAPSHOT_VERSION);
    }

    /// Payloads written before the `orientation` field existed
    /// deserialize cleanly to the default (empty display list, meaning
    /// "unknown") — the interop contract for old clients (contribution)
    /// and old sidecars (composition snapshot) alike.
    #[test]
    fn orientation_field_defaults_when_absent() {
        let json = r#"{"vars":[],"patches":[],"lifecycle_hooks":[],"requested_packages":[]}"#;
        let c: WireContribution = serde_json_lenient::from_str(json).unwrap();
        assert_eq!(c.orientation, WireOrientation::default());
        assert!(
            c.orientation.loadouts_display.is_empty(),
            "expected empty, got {:?}",
            c.orientation.loadouts_display
        );

        let json = r#"{"vars":[],"patches":[],"packages":[],"lifecycle_hooks":[]}"#;
        let c: WireComposition = serde_json_lenient::from_str(json).unwrap();
        assert_eq!(c.orientation, WireOrientation::default());
    }

    /// The contribution round-trips its orientation field.
    #[test]
    fn contribution_orientation_round_trips() {
        let c = WireContribution {
            vars: vec![],
            patches: vec![],
            lifecycle_hooks: vec![],
            requested_packages: vec![],
            orientation: WireOrientation {
                loadouts_display: "default (built-in)".into(),
            },
            entry: None,
        };
        assert_eq!(round_trip(&c), c);
    }

    /// The expanded entry round-trips. An absent list stays absent and an
    /// empty one stays empty.
    #[test]
    fn contribution_entry_round_trips_keeping_absent_lists_apart() {
        let mut entry = WireBoxEntry::new(
            "default",
            "session",
            paths::HostAbsPath::try_new("/work/project").unwrap().into(),
        );
        entry.packages = Some(vec!["ripgrep".into()]);
        entry.lifecycle_hooks = Some(Vec::new());
        let c = WireContribution {
            entry: Some(Box::new(entry)),
            ..WireContribution::default()
        };
        let back = round_trip(&c);
        assert_eq!(back, c);
        let back = back.entry.unwrap();
        assert_eq!(back.vars, None);
        assert_eq!(back.lifecycle_hooks, Some(Vec::new()));

        // A contribution from a client that sends no entry still reads.
        let json = r#"{"vars":[],"patches":[],"lifecycle_hooks":[],"requested_packages":[]}"#;
        let c: WireContribution = serde_json_lenient::from_str(json).unwrap();
        assert_eq!(c.entry, None);
    }
}
