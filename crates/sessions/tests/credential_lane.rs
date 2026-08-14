//! Integration tests for the credential-lane policy gate.
//!
//! Exercises the crate's public surface only: the daemon ships pending
//! lanes, the client gates them against `[credentials]` and its own
//! binding file, and the daemon reassembles what came back.
//!
//! The property under test throughout is that **the binding is the
//! authority**: a project supplies a lane name and an injection shape,
//! and nothing it declares can influence which upstream the lane
//! reaches.

use std::cell::RefCell;
use std::collections::BTreeMap;

use sessions::SessionId;
use sessions::client::handler::handle_response;
use sessions::core::compose::{ComposeError, ComposeOptions, CredentialLane};
use sessions::core::decision::ItemDecision;
use sessions::core::hooks::{HookResult, PolicyHooks, Unapproved};
use sessions::core::policy::{
    CredentialsPolicy, HooksPolicy, PatchesPolicy, UserPolicy, VarsPolicy,
};
use sessions::core::primitives::{Credential, CredentialBindings, CredentialInject};
use sessions::core::source::Source;
use sessions::daemon::composer::{PendingComposeState, resume_from_verdict};
use sessions::wire::policy::WireCredentialVerdict;
use sessions::wire::primitives::{PendingId, WirePendingCredential, WireSource};
use sessions::wire::request::{ContributionResponse, ContributionVerdict, WireContribution};

// =====================================================================
// Support
// =====================================================================

fn session_id() -> SessionId {
    SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
}

fn project_source(path: &str) -> WireSource {
    WireSource::Project {
        path: paths::HostPath::try_new(path).unwrap(),
    }
}

fn no_env(_: &str) -> Result<String, std::env::VarError> {
    Err(std::env::VarError::NotPresent)
}

/// The user's binding file: the sole authority on where a lane's secret
/// comes from and which upstream it may reach.
fn bindings() -> CredentialBindings {
    CredentialBindings::from_toml_str(
        r#"
        [anthropic]
        upstream = "https://api.anthropic.com"
        source   = { env = "ANTHROPIC_API_KEY" }
        "#,
    )
    .expect("binding file parses")
}

/// A one-lane response from `source`, declaring the lane the fixture
/// binding above binds.
fn lane_response(source: WireSource) -> ContributionResponse {
    ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![],
        lifecycle_hooks: vec![],
        credentials: vec![WirePendingCredential {
            id: PendingId::new(0),
            lane: "anthropic".into(),
            header: "x-api-key".into(),
            prefix: String::new(),
            source,
        }],
    }
}

fn gate(
    response: ContributionResponse,
    policy: UserPolicy,
    hooks: &dyn PolicyHooks,
) -> Result<ContributionVerdict, ComposeError> {
    handle_response(
        response,
        &[],
        policy,
        hooks,
        ComposeOptions::default(),
        &bindings(),
        &no_env,
    )
    .map(|(verdict, _)| verdict)
}

/// Panics if any prompt fires — the signal that the policy decided on
/// its own.
struct PanicHooks;
impl PolicyHooks for PanicHooks {
    fn on_var_unapproved(
        &self,
        _: VarsPolicy,
        _: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        panic!("var prompt should not have been invoked")
    }
    fn on_patch_unapproved(
        &self,
        _: PatchesPolicy,
        _: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        panic!("patch prompt should not have been invoked")
    }
    fn on_hook_unapproved(
        &self,
        _: HooksPolicy,
        _: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        panic!("lifecycle-hook prompt should not have been invoked")
    }
    fn on_credential_unapproved(
        &self,
        _: CredentialsPolicy,
        _: &[Unapproved<'_, CredentialLane>],
    ) -> HookResult<CredentialsPolicy> {
        panic!("credential prompt should not have been invoked")
    }
}

/// Implements only the var and patch domains, leaving the credential
/// domain on the trait's default.
struct VarAndPatchOnly;
impl PolicyHooks for VarAndPatchOnly {
    fn on_var_unapproved(
        &self,
        _: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }
    fn on_patch_unapproved(
        &self,
        _: PatchesPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }
}

/// Records the descriptors it was shown, then approves.
struct RecordingHook(RefCell<Vec<CredentialLane>>);
impl PolicyHooks for RecordingHook {
    fn on_var_unapproved(
        &self,
        _: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }
    fn on_patch_unapproved(
        &self,
        _: PatchesPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }
    fn on_credential_unapproved(
        &self,
        _: CredentialsPolicy,
        items: &[Unapproved<'_, CredentialLane>],
    ) -> HookResult<CredentialsPolicy> {
        self.0
            .borrow_mut()
            .extend(items.iter().map(|i| i.item().clone()));
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }
}

fn only_credential_verdict(verdict: &ContributionVerdict) -> &WireCredentialVerdict {
    assert_eq!(verdict.credentials.len(), 1, "expected one lane verdict");
    &verdict.credentials[0]
}

// =====================================================================
// The gate
// =====================================================================

/// An `allow` rule matching the project root approves the lane without
/// prompting, and the upstream on the verdict is the **binding's** —
/// the project never had a field to disagree with.
#[test]
fn allowed_project_gets_the_bound_upstream_without_prompting() {
    let policy =
        UserPolicy::empty().with_credentials(CredentialsPolicy::empty().with_allow(["/repo"]));
    let verdict = gate(lane_response(project_source("/repo")), policy, &PanicHooks).unwrap();
    match only_credential_verdict(&verdict) {
        WireCredentialVerdict::Approved { id, upstream } => {
            assert_eq!(*id, PendingId::new(0));
            assert_eq!(upstream, "https://api.anthropic.com");
        }
        other => panic!("expected Approved, got: {other:?}"),
    }
}

/// A `deny` rule refuses the lane without prompting, and beats an
/// overlapping `allow` — the emergency-stop precedence every domain
/// shares.
#[test]
fn denied_project_is_refused_and_deny_beats_allow() {
    let policy = UserPolicy::empty().with_credentials(
        CredentialsPolicy::empty()
            .with_allow(["/repo"])
            .with_deny(["/repo"]),
    );
    let verdict = gate(lane_response(project_source("/repo")), policy, &PanicHooks).unwrap();
    assert!(
        matches!(
            only_credential_verdict(&verdict),
            WireCredentialVerdict::Denied { .. }
        ),
        "got: {:?}",
        verdict.credentials,
    );
}

/// An `ignore` rule drops the lane silently: no prompt, no failure, and
/// no lane in the session.
#[test]
fn ignored_project_is_dropped_without_prompting() {
    let policy =
        UserPolicy::empty().with_credentials(CredentialsPolicy::empty().with_ignore(["/repo"]));
    let verdict = gate(lane_response(project_source("/repo")), policy, &PanicHooks).unwrap();
    assert!(
        matches!(
            only_credential_verdict(&verdict),
            WireCredentialVerdict::Ignored { .. }
        ),
        "got: {:?}",
        verdict.credentials,
    );
}

/// Silence is not consent: a project no rule mentions reaches the
/// prompt, and what the prompt is shown is the lane, the bound
/// upstream, and the header — a prompt naming only the project would be
/// asking for consent to a destination the user cannot see.
#[test]
fn undecided_project_reaches_the_prompt_with_the_full_descriptor() {
    let hook = RecordingHook(RefCell::new(Vec::new()));
    let verdict = gate(
        lane_response(project_source("/repo")),
        UserPolicy::empty(),
        &hook,
    )
    .unwrap();
    assert!(matches!(
        only_credential_verdict(&verdict),
        WireCredentialVerdict::Approved { .. }
    ));

    let shown = hook.0.borrow();
    assert_eq!(shown.len(), 1, "the user was asked exactly once");
    assert_eq!(shown[0].lane(), "anthropic");
    assert_eq!(shown[0].upstream(), "https://api.anthropic.com");
    assert_eq!(shown[0].header(), "x-api-key");
}

/// A lane tagged as coming from a **package** is refused outright,
/// without consulting the prompt. Packages have no legitimate way to
/// declare one, so its presence is a bug or a bypass attempt.
#[test]
fn package_declared_lane_is_denied_without_prompting() {
    let policy =
        UserPolicy::empty().with_credentials(CredentialsPolicy::empty().with_allow(["**"]));
    let response = lane_response(WireSource::Package {
        name: "claude-code".into(),
    });
    let verdict = gate(response, policy, &PanicHooks).unwrap();
    assert!(
        matches!(
            only_credential_verdict(&verdict),
            WireCredentialVerdict::Denied { .. }
        ),
        "got: {:?}",
        verdict.credentials,
    );
}

/// A lane from the user's own loadout needs no rule and no prompt — it
/// is the user declaring something about themselves.
#[test]
fn loadout_declared_lane_is_auto_allowed() {
    let response = lane_response(WireSource::UserLoadout { name: "dev".into() });
    let verdict = gate(response, UserPolicy::empty(), &PanicHooks).unwrap();
    assert!(
        matches!(
            only_credential_verdict(&verdict),
            WireCredentialVerdict::Approved { .. }
        ),
        "got: {:?}",
        verdict.credentials,
    );
}

/// An implementation that never considered this domain must not be able
/// to grant a lane by omission: the trait's default aborts, so the
/// activation stops loudly instead of quietly composing one.
#[test]
fn a_hook_that_ignores_the_domain_fails_closed() {
    let err = gate(
        lane_response(project_source("/repo")),
        UserPolicy::empty(),
        &VarAndPatchOnly,
    )
    .expect_err("an unimplemented credential prompt must abort");
    assert!(matches!(err, ComposeError::Aborted), "got: {err:?}");
}

/// A lane the user never bound fails the activation naming the lane,
/// rather than composing one with no destination — even for a project
/// the policy already trusts.
#[test]
fn unbound_lane_fails_activation_naming_the_lane() {
    let policy =
        UserPolicy::empty().with_credentials(CredentialsPolicy::empty().with_allow(["/repo"]));
    let mut response = lane_response(project_source("/repo"));
    response.credentials[0].lane = "unbound-name".into();
    let err = gate(response, policy, &PanicHooks).expect_err("an unbound lane must fail");
    match err {
        ComposeError::UnboundCredentialLane { lane, from } => {
            assert_eq!(lane, "unbound-name");
            assert!(matches!(from, Source::Project { .. }));
        }
        other => panic!("expected UnboundCredentialLane, got: {other:?}"),
    }
}

/// A lane the policy refuses needs no binding: the user should not have
/// to bind a name in order to say no to it.
#[test]
fn a_denied_lane_needs_no_binding() {
    let policy =
        UserPolicy::empty().with_credentials(CredentialsPolicy::empty().with_deny(["/repo"]));
    let mut response = lane_response(project_source("/repo"));
    response.credentials[0].lane = "unbound-name".into();
    let verdict =
        gate(response, policy, &PanicHooks).expect("a denied lane must not need a binding");
    assert!(matches!(
        only_credential_verdict(&verdict),
        WireCredentialVerdict::Denied { .. }
    ));
}

// =====================================================================
// Reassembly, daemon-side
// =====================================================================

fn state_with_lanes(lanes: &[(&str, &str)]) -> PendingComposeState {
    PendingComposeState {
        daemon_packages: Vec::new(),
        pending_vars: BTreeMap::new(),
        pending_patches: BTreeMap::new(),
        pending_hooks: BTreeMap::new(),
        pending_credentials: lanes
            .iter()
            .enumerate()
            .map(|(i, (lane, project))| {
                (
                    PendingId::new(u32::try_from(i).unwrap()),
                    sessions::core::source::ProvenancedCredential::new(
                        *lane,
                        Credential::new(CredentialInject::new("x-api-key")),
                        Source::Project {
                            path: paths::HostPath::try_new(*project).unwrap(),
                        },
                    ),
                )
            })
            .collect(),
        client_contribution: WireContribution::default(),
    }
}

/// Two sources declaring the same lane name is a `Conflict`. Left
/// unchecked the two would collapse onto one endpoint variable and the
/// box would reach whichever merged last — with the other lane's
/// credential in play.
#[test]
fn duplicate_lane_name_across_two_sources_is_a_conflict() {
    let state = state_with_lanes(&[("anthropic", "/repo-a"), ("anthropic", "/repo-b")]);
    let verdict = ContributionVerdict {
        session_id: session_id(),
        vars: vec![],
        patches: vec![],
        lifecycle_hooks: vec![],
        credentials: vec![
            WireCredentialVerdict::Approved {
                id: PendingId::new(0),
                upstream: "https://api.anthropic.com".into(),
            },
            WireCredentialVerdict::Approved {
                id: PendingId::new(1),
                upstream: "https://api.anthropic.com".into(),
            },
        ],
    };
    let err = resume_from_verdict(state, verdict).expect_err("a duplicate lane name must conflict");
    assert!(matches!(err, ComposeError::Conflict { .. }), "got: {err:?}");
}

/// The negative control: two projects declaring *different* lanes
/// compose cleanly, so the conflict above is about the name and not
/// about two projects both wanting a credential.
#[test]
fn distinct_lane_names_from_two_projects_compose() {
    let state = state_with_lanes(&[("anthropic", "/repo-a"), ("github-mcp", "/repo-b")]);
    let verdict = ContributionVerdict {
        session_id: session_id(),
        vars: vec![],
        patches: vec![],
        lifecycle_hooks: vec![],
        credentials: vec![
            WireCredentialVerdict::Approved {
                id: PendingId::new(0),
                upstream: "https://api.githubcopilot.com".into(),
            },
            WireCredentialVerdict::Approved {
                id: PendingId::new(1),
                upstream: "https://api.githubcopilot.com".into(),
            },
        ],
    };
    let composition = resume_from_verdict(state, verdict).expect("distinct lanes must compose");
    assert_eq!(composition.credentials().len(), 2);
}

/// A verdict from a client that predates this gate carries no lane
/// decisions at all. Silence must mean "no lane", never "an unvetted
/// one" — so a project's lanes simply don't exist for that client.
#[test]
fn a_client_that_omits_the_verdict_field_yields_zero_lanes() {
    let state = state_with_lanes(&[("anthropic", "/repo")]);
    // Exactly what an older client's payload deserializes to: the key
    // is absent from the JSON, so the field defaults to empty.
    let legacy = serde_json_lenient::from_str::<ContributionVerdict>(&format!(
        r#"{{"session_id":"{}","vars":[],"patches":[]}}"#,
        session_id()
    ))
    .expect("a legacy verdict must load");
    assert!(legacy.credentials.is_empty());

    let composition =
        resume_from_verdict(state, legacy).expect("a legacy verdict must not fault the resume");
    assert!(
        composition.credentials().is_empty(),
        "a lane with no verdict must not compose in",
    );
}
