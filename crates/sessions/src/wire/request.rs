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
    WirePackageRef, WirePendingPatch, WirePendingVar, WireProvenancedHook, WireSessionPatch,
    WireSessionVar,
};
use crate::SessionId;

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

/// Daemon's reply to a `SubmitVerdict`: a terminal "session ready"
/// signal or a protocol-level fault the transport layer didn't
/// catch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionStep {
    /// Composition complete; the session record has been promoted to
    /// [`Active`](crate::SessionStatus::Active) and is ready to use.
    /// Terminal — the client doesn't follow up after receiving this.
    Active {
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
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
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
        let active = SessionStep::Active { id: session_id() };
        let fault = SessionStep::Fault {
            error: WireError::UnknownSessionId,
        };
        assert_eq!(round_trip(&active), active);
        assert_eq!(round_trip(&fault), fault);
    }

    #[test]
    fn session_step_uses_explicit_kind_tag() {
        let s = SessionStep::Fault {
            error: WireError::UnknownSessionId,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains(r#""kind":"fault""#),
            "expected `kind` tag, got: {json}"
        );
    }
}
