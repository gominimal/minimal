//! Wire-form request / response envelopes for client/daemon RPC.
//!
//! Flow:
//!
//! 1. Client → daemon: [`SessionCreateRequest`] containing the
//!    [`WireContribution`] composed from the user's loadouts.
//! 2. Daemon → client: a single [`ContributionResponse`] with the
//!    package- and project-sourced items that need client-side
//!    policy gating.
//! 3. Client → daemon: [`ContributionVerdict`] with per-item
//!    decisions, OR [`Abort`] to bail.

use super::errors::WireError;
use super::policy::{WirePatchVerdict, WireVarVerdict};
use super::primitives::{
    WirePackageRef, WirePendingPatch, WirePendingVar, WireProvenancedHook, WireSessionPatch,
    WireSessionVar, WireSource,
};
use crate::SessionId;

/// Client → Daemon: open a new session.
///
/// Carries everything the client can resolve on its own — the
/// composited user loadouts. No session id (the daemon issues one),
/// no user policy (it's a client-side concern).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionCreateRequest {
    /// Wire protocol version. Daemon rejects unrecognized versions.
    pub protocol_version: u32,
    /// Absolute host path to the project directory.
    pub project_path: paths::HostAbsPath,
    /// The user's already-gated contribution.
    pub contribution: WireContribution,
}

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
/// [`ContributionVerdict`] (or an [`Abort`]), the daemon assembles
/// the session.
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

/// Client → Daemon: bail mid-flow.
///
/// Distinct from a `ContributionVerdict` because aborts are
/// terminal — the daemon should tear down session state — and they
/// carry structured reasons for telemetry / user-facing messages.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Abort {
    /// Session being aborted.
    pub session_id: SessionId,
    /// Why.
    pub reason: AbortReason,
}

/// Why the client aborted.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbortReason {
    /// User policy explicitly denied a contributed item. The daemon
    /// can use `what` + `from` for telemetry without re-running the
    /// policy itself.
    PolicyDenied {
        /// Human-readable identifier of the denied item (var name or
        /// patch source path).
        what: String,
        /// Where the denied item came from.
        from: WireSource,
    },
    /// User cancelled at a prompt.
    UserCancelled,
    /// A `PolicyHooks` callback violated its contract. Diagnostic
    /// only — the message is for telemetry, not the user.
    HookContract {
        /// Short categorical label for the contract violation.
        category: String,
        /// Free-form context naming the offending item or batch.
        context: String,
    },
    /// Anything else; the daemon should treat as opaque.
    Other {
        /// Free-form message.
        message: String,
    },
}

/// Daemon's reply to a session-creation RPC: a terminal "session
/// ready" signal, the next batch of pending items needing
/// client-side gating, or a protocol-level fault the transport layer
/// didn't catch.
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
    /// Pending items awaiting client verdicts.
    Response {
        /// The pending-items payload.
        response: ContributionResponse,
    },
    /// Protocol-level failure detected by the daemon (e.g. unknown
    /// session id, version mismatch). Distinct from a transport error.
    Fault {
        /// Structured fault detail. Nested under a field so its own
        /// `kind` discriminator doesn't collide with this enum's tag.
        error: WireError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::primitives::{
        PendingId, WireHookScript, WireLifecycleHook, WireResolvedPatch, WireResolvedVar,
        WireVarSpec,
    };

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

    fn user_source() -> WireSource {
        WireSource::UserLoadout { name: "dev".into() }
    }

    #[test]
    fn session_create_request_round_trips() {
        let req = SessionCreateRequest {
            protocol_version: 1,
            project_path: paths::HostAbsPath::try_new("/repo").unwrap(),
            contribution: WireContribution {
                vars: vec![WireSessionVar {
                    var: WireResolvedVar {
                        name: "EDITOR".into(),
                        value: "hx".into(),
                    },
                    source: user_source(),
                }],
                patches: vec![WireSessionPatch {
                    patch: WireResolvedPatch {
                        host_path: paths::HostAbsPath::try_new("/home/u/.gitconfig").unwrap(),
                        destination: paths::SandboxRelPath::try_new(".gitconfig").unwrap(),
                    },
                    source: user_source(),
                }],
                lifecycle_hooks: vec![WireProvenancedHook {
                    hook: WireLifecycleHook {
                        on_activate: Some(WireHookScript::Inline {
                            body: "echo hi".into(),
                        }),
                        ..Default::default()
                    },
                    source: user_source(),
                }],
                requested_packages: vec![WirePackageRef {
                    name: "helix".into(),
                    source: user_source(),
                }],
            },
        };
        assert_eq!(round_trip(&req), req);
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
    fn abort_round_trips_all_reasons() {
        let cases = [
            AbortReason::PolicyDenied {
                what: "AWS_SECRET_KEY".into(),
                from: WireSource::Package {
                    name: "evil".into(),
                },
            },
            AbortReason::UserCancelled,
            AbortReason::HookContract {
                category: "decision count mismatch".into(),
                context: "expected 3, got 2".into(),
            },
            AbortReason::Other {
                message: "fs walk panicked".into(),
            },
        ];
        for reason in cases {
            let a = Abort {
                session_id: session_id(),
                reason,
            };
            assert_eq!(round_trip(&a), a);
        }
    }

    #[test]
    fn abort_reason_uses_explicit_kind_tag() {
        let a = AbortReason::UserCancelled;
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            json.contains(r#""kind":"user_cancelled""#),
            "expected `kind` tag, got: {json}"
        );
    }

    #[test]
    fn session_step_round_trips_all_variants() {
        let active = SessionStep::Active { id: session_id() };
        let response = SessionStep::Response {
            response: ContributionResponse {
                session_id: session_id(),
                vars: vec![],
                patches: vec![],
                lifecycle_hooks: vec![],
            },
        };
        let fault = SessionStep::Fault {
            error: WireError::UnknownSessionId,
        };
        assert_eq!(round_trip(&active), active);
        assert_eq!(round_trip(&response), response);
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
