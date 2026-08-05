//! Integration tests for flow 2 of session creation: receiving the
//! daemon's [`ContributionResponse`] and emitting a
//! [`ContributionVerdict`].
//!
//! Same constraints as `client_flow1.rs` — exercises the crate's
//! public surface only.

use std::collections::HashMap;

use camino::Utf8Path;
use sessions::SessionId;
use sessions::client::handler::handle_response;
use sessions::core::compose::{ComposeError, ComposeOptions, SessionVar};
use sessions::core::decision::ItemDecision;
use sessions::core::hooks::{HookResult, PolicyHooks, Unapproved};
use sessions::core::policy::{PatchesPolicy, UserPolicy, VarsPolicy};
use sessions::wire::policy::{WirePatchVerdict, WireVarVerdict};
use sessions::wire::primitives::{
    PendingId, WirePendingPatch, WirePendingVar, WireResolvedVar, WireSessionVar, WireSource,
    WireVarSpec,
};
use sessions::wire::request::ContributionResponse;

// =====================================================================
// Support
// =====================================================================

fn session_id() -> SessionId {
    SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
}

fn project_source() -> WireSource {
    WireSource::Project {
        path: paths::HostPath::try_new("/repo").unwrap(),
    }
}

fn package_source(name: &str) -> WireSource {
    WireSource::Package {
        name: name.to_owned(),
    }
}

fn pinned_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, std::env::VarError> {
    let owned: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name: &str| {
        owned
            .get(name)
            .cloned()
            .ok_or(std::env::VarError::NotPresent)
    }
}

fn fixture_tree<'a>(root: &Utf8Path, files: impl IntoIterator<Item = (&'a str, &'a str)>) {
    for (rel, body) in files {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent.as_std_path()).unwrap();
        }
        std::fs::write(p.as_std_path(), body).unwrap();
    }
}

/// Pre-gated client var (as would be produced by Phase 1's
/// `UserComposer`) for use as `gated_vars` context.
fn gated_var(name: &str, value: &str, loadout: &str) -> SessionVar {
    let wire = WireSessionVar {
        var: WireResolvedVar {
            name: name.to_owned(),
            value: value.to_owned(),
            carries_user_data: true,
        },
        source: WireSource::UserLoadout {
            name: loadout.to_owned(),
        },
    };
    wire.into()
}

struct PassThroughHooks;
impl PolicyHooks for PassThroughHooks {
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

struct AbortHooks;
impl PolicyHooks for AbortHooks {
    fn on_var_unapproved(
        &self,
        _: VarsPolicy,
        _: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        HookResult::abort()
    }
    fn on_patch_unapproved(
        &self,
        _: PatchesPolicy,
        _: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        HookResult::abort()
    }
}

/// Hook that should never be reached.
struct PanicHooks;
impl PolicyHooks for PanicHooks {
    fn on_var_unapproved(
        &self,
        _: VarsPolicy,
        _: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        panic!("var hook should not have been invoked")
    }
    fn on_patch_unapproved(
        &self,
        _: PatchesPolicy,
        _: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        panic!("patch hook should not have been invoked")
    }
    // Overridden rather than left to the trait's fail-closed default:
    // the default aborts, which a test asserting "no prompt happened"
    // could not distinguish from a policy that decided on its own.
    fn on_hook_unapproved(
        &self,
        _: sessions::core::policy::HooksPolicy,
        _: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<sessions::core::policy::HooksPolicy> {
        panic!("lifecycle-hook prompt should not have been invoked")
    }
}

fn empty_response() -> ContributionResponse {
    ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![],
        lifecycle_hooks: vec![],
    }
}

// =====================================================================
// Tests
// =====================================================================

/// Empty pending → empty verdict echoing the session id.
#[test]
fn empty_response_produces_empty_verdict() {
    let (verdict, _) = handle_response(
        empty_response(),
        &[],
        UserPolicy::empty(),
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert_eq!(verdict.session_id, session_id());
    assert!(verdict.vars.is_empty());
    assert!(verdict.patches.is_empty());
}

/// A Specified pending var that matches the policy's `allow` rule
/// is auto-approved; the verdict carries the value the daemon will
/// see.
#[test]
fn specified_var_allow_listed_is_approved() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "EDITOR".into(),
            spec: WireVarSpec::Specified { value: "hx".into() },
            source: package_source("helix"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let vars_policy = VarsPolicy::empty().try_with_allow(["EDITOR"]).unwrap();
    let policy = UserPolicy::empty().with_vars(vars_policy);

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert_eq!(verdict.vars.len(), 1);
    match &verdict.vars[0] {
        WireVarVerdict::Approved { id, value } => {
            assert_eq!(*id, PendingId::new(1));
            assert_eq!(value.name, "EDITOR");
            assert_eq!(value.value, "hx");
        }
        other => panic!("expected Approved, got: {other:?}"),
    }
}

/// `Inherit`-shaped pending var resolves against the client's env.
#[test]
fn inherit_var_resolves_against_env() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "LANG".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("locales"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let policy =
        UserPolicy::empty().with_vars(VarsPolicy::empty().try_with_allow(["LANG"]).unwrap());
    let env = pinned_env(&[("LANG", "sjn_IV")]);

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &env,
    )
    .unwrap();
    match &verdict.vars[0] {
        WireVarVerdict::Approved { value, .. } => assert_eq!(value.value, "sjn_IV"),
        other => panic!("expected Approved, got: {other:?}"),
    }
}

/// `InheritWithDefault` falls back when the env is missing.
#[test]
fn inherit_with_default_falls_back() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "LANG".into(),
            spec: WireVarSpec::InheritWithDefault {
                default: "sjn_IV".into(),
            },
            source: package_source("locales"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let policy =
        UserPolicy::empty().with_vars(VarsPolicy::empty().try_with_allow(["LANG"]).unwrap());

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    match &verdict.vars[0] {
        WireVarVerdict::Approved { value, .. } => assert_eq!(value.value, "sjn_IV"),
        other => panic!("expected Approved, got: {other:?}"),
    }
}

/// `Inherit` with a missing env value → [`ComposeError::VarResolution`].
#[test]
fn inherit_var_missing_env_errors() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "MUST_BE_SET".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("strict"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let err = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap_err();
    assert!(
        matches!(err, ComposeError::VarResolution { ref name, .. } if name == "MUST_BE_SET"),
        "got: {err:?}",
    );
}

/// A `deny` rule on a pending var produces a per-item Denied verdict
/// but doesn't abort sibling items.
#[test]
fn policy_deny_per_item() {
    // `Inherit` (not `Specified`) so the resolved vars have
    // `carries_user_data = true` — the policy gate only fires on
    // vars that move user env data into the sandbox; a hardcoded
    // literal isn't a leak vector and would auto-approve.
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![
            WirePendingVar {
                id: PendingId::new(1),
                name: "AWS_KEY".into(),
                spec: WireVarSpec::Inherit,
                source: package_source("evil"),
                carries_user_data: false,
            },
            WirePendingVar {
                id: PendingId::new(2),
                name: "EDITOR".into(),
                spec: WireVarSpec::Inherit,
                source: package_source("helix"),
                carries_user_data: false,
            },
        ],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let vars_policy = VarsPolicy::empty()
        .try_with_deny(["AWS_*"])
        .unwrap()
        .try_with_allow(["EDITOR"])
        .unwrap();
    let policy = UserPolicy::empty().with_vars(vars_policy);

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[("AWS_KEY", "leaked"), ("EDITOR", "hx")]),
    )
    .unwrap();

    let by_id: HashMap<u32, &WireVarVerdict> = verdict
        .vars
        .iter()
        .map(|v| (verdict_var_id(v), v))
        .collect();
    assert!(matches!(by_id.get(&1), Some(WireVarVerdict::Denied { .. })));
    assert!(matches!(
        by_id.get(&2),
        Some(WireVarVerdict::Approved { .. })
    ));
}

/// `ignore` rule produces an Ignored verdict. `Inherit` (not
/// `Specified`) so `carries_user_data` is true and the gate fires.
#[test]
fn policy_ignore_per_item() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "_TMP".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("noisy"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let vars_policy = VarsPolicy::empty().try_with_ignore(["_*"]).unwrap();
    let policy = UserPolicy::empty().with_vars(vars_policy);

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[("_TMP", "x")]),
    )
    .unwrap();
    assert!(matches!(verdict.vars[0], WireVarVerdict::Ignored { .. }));
}

/// A pending var that policy can't auto-decide goes to the hook;
/// `AllowOnce` produces an Approved verdict.
#[test]
fn hook_approves_unapproved() {
    // `Inherit` so the var carries user data and reaches the hook.
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "MY_VAR".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("p"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let (verdict, _) = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &PassThroughHooks,
        ComposeOptions::default(),
        &pinned_env(&[("MY_VAR", "v")]),
    )
    .unwrap();
    assert!(matches!(verdict.vars[0], WireVarVerdict::Approved { .. }));
}

/// Hook returns Abort → [`ComposeError::Aborted`]. `Inherit` so
/// `carries_user_data` is true and the var reaches the hook (a
/// hardcoded literal would auto-approve at the gate).
#[test]
fn hook_abort_propagates() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "MY_VAR".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("p"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let err = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &AbortHooks,
        ComposeOptions::default(),
        &pinned_env(&[("MY_VAR", "v")]),
    )
    .unwrap_err();
    assert!(matches!(err, ComposeError::Aborted), "got: {err:?}");
}

/// A pending patch's source pattern references a `$VAR` defined in
/// the gated client vars (from Phase 1). Expansion succeeds and the
/// matched files emit verdicts.
#[test]
fn patch_source_uses_gated_vars() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("helix/themes/nord.toml", "# nord\n")]);

    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![WirePendingPatch {
            id: PendingId::new(1),
            source_pattern: "$HELIX_CONFIG/themes/*.toml".into(),
            destination: paths::SandboxRelPath::try_new(".config/helix/themes").unwrap(),
            description: None,
            source: package_source("helix"),
        }],
        lifecycle_hooks: vec![],
    };
    let gated = vec![gated_var(
        "HELIX_CONFIG",
        root.join("helix").as_str(),
        "dev",
    )];
    let policy =
        UserPolicy::empty().with_patches(PatchesPolicy::empty().with_allow(["/**/*.toml"]));

    let (verdict, _) = handle_response(
        response,
        &gated,
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert_eq!(verdict.patches.len(), 1);
    match &verdict.patches[0] {
        WirePatchVerdict::Approved { id, host_path, .. } => {
            assert_eq!(*id, PendingId::new(1));
            assert!(host_path.as_str().ends_with("helix/themes/nord.toml"));
        }
        other => panic!("expected Approved, got: {other:?}"),
    }
}

/// A pending var defined earlier in this response is visible to
/// pending patches in the same response.
#[test]
fn patch_source_uses_batch_approved_vars() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("helix/themes/nord.toml", "# nord\n")]);

    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "HELIX_CONFIG".into(),
            spec: WireVarSpec::Specified {
                value: root.join("helix").to_string(),
            },
            source: package_source("helix"),
            carries_user_data: false,
        }],
        patches: vec![WirePendingPatch {
            id: PendingId::new(2),
            source_pattern: "$HELIX_CONFIG/themes/*.toml".into(),
            destination: paths::SandboxRelPath::try_new(".config/helix/themes").unwrap(),
            description: None,
            source: package_source("helix"),
        }],
        lifecycle_hooks: vec![],
    };
    let policy = UserPolicy::empty()
        .with_vars(
            VarsPolicy::empty()
                .try_with_allow(["HELIX_CONFIG"])
                .unwrap(),
        )
        .with_patches(PatchesPolicy::empty().with_allow(["/**/*.toml"]));

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert!(matches!(verdict.vars[0], WireVarVerdict::Approved { .. }));
    assert!(matches!(
        verdict.patches[0],
        WirePatchVerdict::Approved { .. }
    ));
}

/// Companion to `patch_source_uses_batch_approved_vars` that
/// actually exercises the vars-allow-list path. The parent uses a
/// `Specified` var with `carries_user_data: false`, which the
/// classifier short-circuits before the allow list ever runs — so
/// a regression that broke `try_with_allow` (e.g. inverting
/// deny/allow precedence, or dropping the allow check entirely)
/// would leave that test green. This one ships an `Inherit`-shaped
/// var (`carries_user_data: true`), forcing the classifier to
/// consult the policy — flipping the allow rule off (or off-by-
/// one on the glob) has to break the assertion here.
#[test]
fn allow_rule_gates_env_derived_var() {
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "HELIX_CONFIG".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("helix"),
            carries_user_data: true,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let policy = UserPolicy::empty().with_vars(
        VarsPolicy::empty()
            .try_with_allow(["HELIX_CONFIG"])
            .unwrap(),
    );

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        // `Inherit` needs the env to actually resolve the value —
        // pin it here so the test doesn't depend on the ambient
        // shell.
        &pinned_env(&[("HELIX_CONFIG", "/etc/helix")]),
    )
    .unwrap();
    match &verdict.vars[0] {
        WireVarVerdict::Approved { value, .. } => {
            assert_eq!(value.name, "HELIX_CONFIG");
            assert_eq!(value.value, "/etc/helix");
            assert!(
                value.carries_user_data,
                "the resolved value came from env — provenance bit must survive",
            );
        }
        other => panic!("expected Approved via allow rule, got: {other:?}"),
    }
}

/// A multi-file glob fan-out yields one verdict per matched file;
/// the deny pattern can reject one without aborting the others.
#[test]
fn multi_file_patch_yields_per_file_verdicts() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(
        root,
        [
            ("themes/nord.toml", "# nord\n"),
            ("themes/nord-light.toml", "# light\n"),
            ("themes/draft.toml.bak", "stale\n"),
        ],
    );

    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![WirePendingPatch {
            id: PendingId::new(1),
            source_pattern: format!("{root}/themes/*"),
            destination: paths::SandboxRelPath::try_new(".config/helix/themes").unwrap(),
            description: None,
            source: project_source(),
        }],
        lifecycle_hooks: vec![],
    };
    let policy = UserPolicy::empty().with_patches(
        PatchesPolicy::empty()
            .with_allow(["/**/*.toml"])
            .with_deny(["/**/*.bak"]),
    );

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();

    // Three matched files → three verdicts under the same pending id.
    assert_eq!(verdict.patches.len(), 3);
    let id = PendingId::new(1);
    for v in &verdict.patches {
        assert_eq!(verdict_patch_id(v), id);
    }
    let approved: Vec<&str> = verdict
        .patches
        .iter()
        .filter_map(|v| match v {
            WirePatchVerdict::Approved { host_path, .. } => Some(host_path.as_str()),
            _ => None,
        })
        .collect();
    let denied: Vec<&str> = verdict
        .patches
        .iter()
        .filter_map(|v| match v {
            WirePatchVerdict::Denied { host_path, .. } => Some(host_path.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(approved.len(), 2);
    assert_eq!(denied.len(), 1);
    assert!(
        denied[0].ends_with("draft.toml.bak"),
        "expected .bak file in denied list, got: {denied:?}",
    );
}

/// Build a one-hook response from `source`.
fn hook_response(source: WireSource) -> ContributionResponse {
    use sessions::wire::primitives::{
        PendingId, WireHookScript, WireLifecycleHook, WirePendingHook,
    };
    ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![],
        lifecycle_hooks: vec![WirePendingHook {
            id: PendingId::new(0),
            hook: WireLifecycleHook {
                on_activate: Some(WireHookScript::Inline {
                    body: "echo hi".into(),
                    timeout_secs: 60,
                }),
                ..Default::default()
            },
            source,
        }],
    }
}

/// A hook tagged as coming from a **package** is denied outright,
/// without consulting the prompt (`PanicHooks` would fire if it were
/// consulted). Packages have no legitimate way to declare a hook, so
/// one appearing here is a bug or a bypass attempt and must not run.
#[test]
fn package_declared_hook_is_denied_without_prompting() {
    use sessions::wire::policy::WireHookVerdict;

    let (verdict, _) = handle_response(
        hook_response(package_source("helix")),
        &[],
        UserPolicy::empty(),
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert!(verdict.vars.is_empty());
    assert!(verdict.patches.is_empty());
    assert!(
        matches!(
            verdict.lifecycle_hooks.as_slice(),
            [WireHookVerdict::Denied { .. }]
        ),
        "got: {:?}",
        verdict.lifecycle_hooks,
    );
}

/// A project-declared hook with an empty policy has no rule to decide
/// it, so it routes to the prompt rather than being auto-approved.
/// `PanicHooks` panics when consulted, which is exactly the signal
/// that the gate reached the prompt.
#[test]
#[should_panic(expected = "lifecycle-hook prompt should not have been invoked")]
fn project_declared_hook_with_no_rule_reaches_the_prompt() {
    let _ = handle_response(
        hook_response(project_source()),
        &[],
        UserPolicy::empty(),
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    );
}

/// An `allow` rule matching the project root approves its hooks
/// without prompting.
#[test]
fn project_hook_allowed_by_policy_skips_the_prompt() {
    use sessions::core::policy::HooksPolicy;
    use sessions::wire::policy::WireHookVerdict;

    let policy = UserPolicy::empty().with_hooks(HooksPolicy::empty().with_allow(["/repo"]));
    let (verdict, _) = handle_response(
        hook_response(project_source()),
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert!(
        matches!(
            verdict.lifecycle_hooks.as_slice(),
            [WireHookVerdict::Approved { .. }]
        ),
        "got: {:?}",
        verdict.lifecycle_hooks,
    );
}

/// A `deny` rule refuses the project's hooks without prompting, and
/// beats an overlapping `allow` — the same emergency-stop precedence
/// the other two domains use.
#[test]
fn project_hook_denied_by_policy_beats_allow() {
    use sessions::core::policy::HooksPolicy;
    use sessions::wire::policy::WireHookVerdict;

    let policy = UserPolicy::empty().with_hooks(
        HooksPolicy::empty()
            .with_allow(["/repo"])
            .with_deny(["/repo"]),
    );
    let (verdict, _) = handle_response(
        hook_response(project_source()),
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert!(
        matches!(
            verdict.lifecycle_hooks.as_slice(),
            [WireHookVerdict::Denied { .. }]
        ),
        "got: {:?}",
        verdict.lifecycle_hooks,
    );
}

/// An `ignore` rule drops the project's hooks silently — no prompt,
/// and no denial that would abort the activation.
#[test]
fn project_hook_ignored_by_policy_is_dropped_quietly() {
    use sessions::core::policy::HooksPolicy;
    use sessions::wire::policy::WireHookVerdict;

    let policy = UserPolicy::empty().with_hooks(HooksPolicy::empty().with_ignore(["/repo"]));
    let (verdict, _) = handle_response(
        hook_response(project_source()),
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert!(
        matches!(
            verdict.lifecycle_hooks.as_slice(),
            [WireHookVerdict::Ignored { .. }]
        ),
        "got: {:?}",
        verdict.lifecycle_hooks,
    );
}

/// Patch-side parity for `policy_ignore_per_item`: a file matched
/// by the patch policy's `ignore` rule produces an `Ignored`
/// verdict (not Approved, not Denied).
#[test]
fn patch_policy_ignore_produces_ignored_verdict() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("themes/draft.toml", "stale\n")]);

    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![WirePendingPatch {
            id: PendingId::new(1),
            source_pattern: format!("{root}/themes/*.toml"),
            destination: paths::SandboxRelPath::try_new(".config/helix/themes").unwrap(),
            description: None,
            source: project_source(),
        }],
        lifecycle_hooks: vec![],
    };
    let policy = UserPolicy::empty().with_patches(
        PatchesPolicy::empty()
            .with_ignore(["/**/draft.toml"])
            .with_allow(["/**/*.toml"]),
    );

    let (verdict, _) = handle_response(
        response,
        &[],
        policy,
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();
    assert_eq!(verdict.patches.len(), 1);
    assert!(matches!(
        verdict.patches[0],
        WirePatchVerdict::Ignored { .. }
    ));
}

/// Var-side parity for `unapproved_files_batched_into_one_hook_call`:
/// two unapproved pending vars produce a single hook invocation
/// carrying both items, not one call per var.
#[test]
fn unapproved_vars_batched_into_one_hook_call() {
    use std::cell::RefCell;

    struct CountingHook {
        calls: RefCell<usize>,
        batch_sizes: RefCell<Vec<usize>>,
    }
    impl PolicyHooks for CountingHook {
        fn on_var_unapproved(
            &self,
            _: VarsPolicy,
            items: &[Unapproved<'_, str>],
        ) -> HookResult<VarsPolicy> {
            *self.calls.borrow_mut() += 1;
            self.batch_sizes.borrow_mut().push(items.len());
            HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
        }
        fn on_patch_unapproved(
            &self,
            _: PatchesPolicy,
            _: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchesPolicy> {
            panic!("patch hook not expected")
        }
    }

    // `Inherit` on both so `carries_user_data` is true and the
    // gate routes them to the hook — literals would auto-approve.
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![
            WirePendingVar {
                id: PendingId::new(1),
                name: "ONE".into(),
                spec: WireVarSpec::Inherit,
                source: package_source("a"),
                carries_user_data: false,
            },
            WirePendingVar {
                id: PendingId::new(2),
                name: "TWO".into(),
                spec: WireVarSpec::Inherit,
                source: package_source("b"),
                carries_user_data: false,
            },
        ],
        patches: vec![],
        lifecycle_hooks: vec![],
    };

    let hook = CountingHook {
        calls: RefCell::new(0),
        batch_sizes: RefCell::new(Vec::new()),
    };
    let (verdict, _) = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &hook,
        ComposeOptions::default(),
        &pinned_env(&[("ONE", "1"), ("TWO", "2")]),
    )
    .unwrap();

    assert_eq!(*hook.calls.borrow(), 1, "expected exactly one hook call");
    assert_eq!(
        *hook.batch_sizes.borrow(),
        vec![2],
        "expected both vars in the same batch",
    );
    assert_eq!(verdict.vars.len(), 2);
}

// ---------------------------------------------------------------------
// Error / edge-case coverage
// ---------------------------------------------------------------------

/// Hook returns `UseRule` along with an `updated_policy` that
/// auto-approves the item via a new allow rule. Verdict is
/// `Approved`.
#[test]
fn hook_use_rule_with_updated_policy_approves() {
    struct UseRuleHook;
    impl PolicyHooks for UseRuleHook {
        fn on_var_unapproved(
            &self,
            policy: VarsPolicy,
            items: &[Unapproved<'_, str>],
        ) -> HookResult<VarsPolicy> {
            let updated = policy.try_with_allow(["MY_*"]).unwrap();
            HookResult::decided_with_policy(vec![ItemDecision::UseRule; items.len()], updated)
        }
        fn on_patch_unapproved(
            &self,
            _: PatchesPolicy,
            _: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchesPolicy> {
            panic!("not expected")
        }
    }

    // `Inherit` so the var carries user data and reaches the hook.
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "MY_VAR".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("p"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let (verdict, _) = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &UseRuleHook,
        ComposeOptions::default(),
        &pinned_env(&[("MY_VAR", "v")]),
    )
    .unwrap();
    assert!(matches!(verdict.vars[0], WireVarVerdict::Approved { .. }));
}

/// Hook returns `UseRule` but the policy still can't decide the item
/// (no `updated_policy` and no matching rule) → `HookContract`.
#[test]
fn hook_use_rule_without_decision_errors_as_hook_contract() {
    struct BadUseRuleHook;
    impl PolicyHooks for BadUseRuleHook {
        fn on_var_unapproved(
            &self,
            _: VarsPolicy,
            items: &[Unapproved<'_, str>],
        ) -> HookResult<VarsPolicy> {
            HookResult::decided(vec![ItemDecision::UseRule; items.len()])
        }
        fn on_patch_unapproved(
            &self,
            _: PatchesPolicy,
            _: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchesPolicy> {
            panic!("not expected")
        }
    }

    // `Inherit` so the var carries user data and reaches the hook.
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "MY_VAR".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("p"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let err = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &BadUseRuleHook,
        ComposeOptions::default(),
        &pinned_env(&[("MY_VAR", "v")]),
    )
    .unwrap_err();
    assert!(
        matches!(err, ComposeError::HookContract { .. }),
        "got: {err:?}",
    );
}

/// Hook returns the wrong number of decisions → `HookContract`.
#[test]
fn hook_wrong_decision_count_errors_as_hook_contract() {
    struct WrongCountHook;
    impl PolicyHooks for WrongCountHook {
        fn on_var_unapproved(
            &self,
            _: VarsPolicy,
            _items: &[Unapproved<'_, str>],
        ) -> HookResult<VarsPolicy> {
            // Always emit two, regardless of input length.
            HookResult::decided(vec![ItemDecision::AllowOnce, ItemDecision::AllowOnce])
        }
        fn on_patch_unapproved(
            &self,
            _: PatchesPolicy,
            _: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchesPolicy> {
            panic!("not expected")
        }
    }

    // `Inherit` so the var carries user data and reaches the hook.
    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![WirePendingVar {
            id: PendingId::new(1),
            name: "MY_VAR".into(),
            spec: WireVarSpec::Inherit,
            source: package_source("p"),
            carries_user_data: false,
        }],
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let err = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &WrongCountHook,
        ComposeOptions::default(),
        &pinned_env(&[("MY_VAR", "v")]),
    )
    .unwrap_err();
    assert!(
        matches!(err, ComposeError::HookContract { .. }),
        "got: {err:?}",
    );
}

/// A pending patch whose destination violates `PatchDest` invariants
/// surfaces as [`ComposeError::InvalidPendingPatchDest`].
#[test]
fn invalid_pending_patch_dest_errors() {
    use sessions::core::primitives::PatchError;

    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![WirePendingPatch {
            id: PendingId::new(1),
            source_pattern: "/tmp/nonexistent/*".into(),
            // Empty path passes `SandboxRelPath` validation but
            // `PatchDest::try_new` rejects it.
            destination: paths::SandboxRelPath::try_new("").unwrap(),
            description: None,
            source: package_source("p"),
        }],
        lifecycle_hooks: vec![],
    };
    let err = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &PanicHooks,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            ComposeError::InvalidPendingPatchDest {
                source: PatchError::EmptyDest
            }
        ),
        "got: {err:?}",
    );
}

/// Two pending patches whose source patterns each yield one
/// unapproved file: the handler batches them into a *single* hook
/// call so the user sees one prompt per response, not one per
/// pending patch.
#[test]
fn unapproved_files_batched_into_one_hook_call() {
    use std::cell::RefCell;

    struct CountingHook {
        calls: RefCell<usize>,
        batch_sizes: RefCell<Vec<usize>>,
    }
    impl PolicyHooks for CountingHook {
        fn on_var_unapproved(
            &self,
            _: VarsPolicy,
            _: &[Unapproved<'_, str>],
        ) -> HookResult<VarsPolicy> {
            panic!("var hook not expected")
        }
        fn on_patch_unapproved(
            &self,
            _: PatchesPolicy,
            items: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchesPolicy> {
            *self.calls.borrow_mut() += 1;
            self.batch_sizes.borrow_mut().push(items.len());
            HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("a/conf.toml", "a"), ("b/conf.toml", "b")]);

    let response = ContributionResponse {
        session_id: session_id(),
        vars: vec![],
        patches: vec![
            WirePendingPatch {
                id: PendingId::new(1),
                source_pattern: format!("{root}/a/*.toml"),
                destination: paths::SandboxRelPath::try_new(".config/a").unwrap(),
                description: None,
                source: package_source("a"),
            },
            WirePendingPatch {
                id: PendingId::new(2),
                source_pattern: format!("{root}/b/*.toml"),
                destination: paths::SandboxRelPath::try_new(".config/b").unwrap(),
                description: None,
                source: package_source("b"),
            },
        ],
        lifecycle_hooks: vec![],
    };

    let hook = CountingHook {
        calls: RefCell::new(0),
        batch_sizes: RefCell::new(Vec::new()),
    };
    let (verdict, _) = handle_response(
        response,
        &[],
        UserPolicy::empty(),
        &hook,
        ComposeOptions::default(),
        &pinned_env(&[]),
    )
    .unwrap();

    assert_eq!(*hook.calls.borrow(), 1, "expected exactly one hook call");
    assert_eq!(
        *hook.batch_sizes.borrow(),
        vec![2],
        "expected both files in the same batch",
    );
    assert_eq!(verdict.patches.len(), 2);
    let ids: Vec<_> = verdict.patches.iter().map(verdict_patch_id).collect();
    assert!(ids.contains(&PendingId::new(1)));
    assert!(ids.contains(&PendingId::new(2)));
}

// =====================================================================
// Helpers for verdict introspection
// =====================================================================

fn verdict_var_id(v: &WireVarVerdict) -> u32 {
    let id = match v {
        WireVarVerdict::Approved { id, .. }
        | WireVarVerdict::Denied { id, .. }
        | WireVarVerdict::Ignored { id, .. } => *id,
    };
    id.get()
}

fn verdict_patch_id(v: &WirePatchVerdict) -> PendingId {
    match v {
        WirePatchVerdict::Approved { id, .. }
        | WirePatchVerdict::Denied { id, .. }
        | WirePatchVerdict::Ignored { id, .. } => *id,
    }
}
