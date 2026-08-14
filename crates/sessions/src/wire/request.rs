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
use super::policy::{WireCredentialVerdict, WireHookVerdict, WirePatchVerdict, WireVarVerdict};
use super::primitives::{
    WireCredentialLane, WireOrientation, WirePackageRef, WirePendingCredential, WirePendingHook,
    WirePendingPatch, WirePendingVar, WireProvenancedHook, WireSessionPatch, WireSessionVar,
};
use crate::SessionId;

/// Snapshot format version for [`WireComposition`]. Bumped when the
/// on-disk shape changes in a way older daemons can't tolerate.
///
/// - **1** — lifecycle hooks carried `on_failure` and no `description`
///   or per-script `timeout`.
/// - **2** — hooks carry `description`, `on_attach`, `on_detach`, and a
///   per-script `timeout_secs`; `on_failure` is gone.
///
/// Credential lanes did **not** bump this. The field is purely additive
/// and serde-defaulted, so the shape is tolerated in both directions: an
/// older daemon ignores a key it doesn't know, and a newer one reads a
/// snapshot without the key as "no lanes" — which is also the correct
/// answer, since a session composed before lanes existed has none. A
/// bump is for a change an older daemon *cannot* tolerate.
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
    /// Credential lanes that passed the user policy gate client-side.
    /// Empty until a loadout can declare one — a project's lanes travel
    /// the other way, as pending items the client votes on.
    /// Serde-defaulted so payloads from clients that predate the field
    /// deserialize cleanly.
    #[serde(default)]
    pub credentials: Vec<WireCredentialLane>,
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
    /// Credential lanes that survived the policy gate: lane name, bound
    /// upstream, and injected header. No value is here, which is what
    /// makes this sidecar's `0644` mode survivable. Serde-defaulted so
    /// sidecars written before the field existed deserialize cleanly.
    #[serde(default)]
    pub credentials: Vec<WireCredentialLane>,
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
            credentials: c.credentials().iter().cloned().map(Into::into).collect(),
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
    /// Credential lanes awaiting the credentials-policy gate.
    /// Project-declared only, for the same reason as hooks.
    /// Serde-defaulted so a response from a daemon that predates the
    /// gate deserializes as "no lanes".
    #[serde(default)]
    pub credentials: Vec<WirePendingCredential>,
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
    /// One verdict per pending credential lane. Serde-defaulted on the
    /// same fail-closed contract as `lifecycle_hooks`: a lane the
    /// verdict never mentions is dropped, so a client that predates
    /// this gate yields zero lanes rather than unvetted ones.
    #[serde(default)]
    pub credentials: Vec<WireCredentialVerdict>,
}

/// Daemon's reply to a `SubmitVerdict`: composition finalized (the
/// record has moved from `Pending` to
/// [`Materializing`](crate::SessionStatus::Materializing), not yet
/// `Active`) or a protocol-level fault the transport layer didn't
/// catch.
///
/// The client follows up with a patches upload
/// (`WorkspacePatchesTarZst`) and then `FinalizeSession` to
/// actually promote the record to
/// [`Active`](crate::SessionStatus::Active). Only after that step
/// is the session attachable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionStep {
    /// Composition complete; the session record has been promoted to
    /// [`Materializing`](crate::SessionStatus::Materializing). The
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
            credentials: vec![WirePendingCredential {
                id: PendingId::new(2),
                lane: "anthropic".into(),
                header: "x-api-key".into(),
                prefix: String::new(),
                source: WireSource::Project {
                    path: paths::HostPath::try_new("/repo").unwrap(),
                },
            }],
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
            credentials: vec![WireCredentialVerdict::Approved {
                id: PendingId::new(4),
                upstream: "https://api.anthropic.com".into(),
            }],
        };
        assert_eq!(round_trip(&v), v);
    }

    /// A verdict from a client that predates the hooks and credentials
    /// gates carries neither key at all. It must deserialize to empty
    /// lists — which the daemon treats as "approve nothing" — rather
    /// than failing the message.
    #[test]
    fn contribution_verdict_without_gated_fields_deserializes_empty() {
        let json = format!(
            r#"{{"session_id":"{}","vars":[],"patches":[]}}"#,
            session_id()
        );
        let v: ContributionVerdict =
            serde_json_lenient::from_str(&json).expect("legacy verdict must load");
        assert!(v.lifecycle_hooks.is_empty());
        assert!(v.credentials.is_empty());
    }

    #[test]
    fn session_step_round_trips_all_variants() {
        let materialized = SessionStep::Materialized { id: session_id() };
        let fault = SessionStep::Fault {
            error: WireError::UnknownSessionId,
        };
        assert_eq!(round_trip(&materialized), materialized);
        assert_eq!(round_trip(&fault), fault);
    }

    #[test]
    fn session_step_uses_explicit_kind_tag() {
        let s = SessionStep::Fault {
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
            credentials: vec![WireCredentialLane {
                lane: "anthropic".into(),
                upstream: "https://api.anthropic.com".into(),
                header: "x-api-key".into(),
                source: WireSource::Project {
                    path: paths::HostPath::try_new("/repo").unwrap(),
                },
            }],
        };
        assert_eq!(round_trip(&c), c);
    }

    /// A persisted lane survives the snapshot → domain → snapshot trip
    /// intact, so a restart re-applies the lane the user approved rather
    /// than a differently-pointed one.
    #[test]
    fn composition_snapshot_round_trips_a_lane() {
        let lane = WireCredentialLane {
            lane: "anthropic".into(),
            upstream: "https://api.anthropic.com".into(),
            header: "x-api-key".into(),
            source: WireSource::Project {
                path: paths::HostPath::try_new("/repo").unwrap(),
            },
        };
        let snapshot = WireComposition {
            credentials: vec![lane.clone()],
            ..Default::default()
        };
        let composition = crate::core::compose::Composition::try_from(snapshot)
            .expect("snapshot with a lane loads");
        assert_eq!(WireComposition::from(&composition).credentials, [lane]);
    }

    /// A snapshot written before lanes existed loads as "no lanes",
    /// which is also the truth about that session.
    #[test]
    fn composition_snapshot_without_credentials_deserializes_empty() {
        let json = r#"{"version":2,"vars":[],"patches":[],"packages":[],"lifecycle_hooks":[]}"#;
        let c: WireComposition = serde_json_lenient::from_str(json).unwrap();
        assert!(c.credentials.is_empty());
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
        assert!(c.orientation.loadouts_display.is_empty());

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
            credentials: vec![],
        };
        assert_eq!(round_trip(&c), c);
    }
}
