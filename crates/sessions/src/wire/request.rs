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
use super::policy::{WirePatchVerdict, WireVarVerdict};
use super::primitives::{
    WireOrientation, WirePackageRef, WirePendingPatch, WirePendingVar, WireProvenancedHook,
    WireSessionPatch, WireSessionVar,
};
use crate::SessionId;

/// Snapshot format version for [`WireComposition`]. Bumped when the
/// on-disk shape changes in a way older daemons can't tolerate.
const COMPOSITION_SNAPSHOT_VERSION: u32 = 1;

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
/// ambiguity; the current and only version is
/// [`COMPOSITION_SNAPSHOT_VERSION`] (1).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireComposition {
    /// Snapshot format version. Defaults to
    /// [`COMPOSITION_SNAPSHOT_VERSION`] so sidecars written by daemons
    /// that predate the field deserialize cleanly.
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
    COMPOSITION_SNAPSHOT_VERSION
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
    /// Lifecycle hooks (no policy applies; pass through to client).
    pub lifecycle_hooks: Vec<WireProvenancedHook>,
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
        };
        assert_eq!(round_trip(&v), v);
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
        };
        assert_eq!(round_trip(&c), c);
    }

    #[test]
    fn composition_snapshot_defaults_version_to_one() {
        // A sidecar written without the `version` field (e.g. by a
        // hypothetical future writer that omits it) should default to
        // version 1, not 0.
        let json = r#"{"vars":[],"patches":[],"packages":[],"lifecycle_hooks":[]}"#;
        let c: WireComposition = serde_json_lenient::from_str(json).unwrap();
        assert_eq!(c.version, COMPOSITION_SNAPSHOT_VERSION);
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
        };
        assert_eq!(round_trip(&c), c);
    }
}
