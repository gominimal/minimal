use super::*;
use crate::core::primitives::{Patch, PatchDest, VarValue};
use camino::Utf8Path;
use std::cell::RefCell;

// =================================================================
// Shared helpers + hook fixtures
// =================================================================

fn user_source() -> Source {
    Source::UserLoadout {
        name: "test".into(),
    }
}

fn project_source() -> Source {
    Source::Project {
        path: paths::HostPath::try_new("/repo").unwrap(),
    }
}

fn pv_with(name: &str, source: Source) -> ProvenancedVar {
    pv_value(name, "x", source)
}

fn pv(name: &str) -> ProvenancedVar {
    pv_with(name, project_source())
}

fn pv_value(name: &str, value: &str, source: Source) -> ProvenancedVar {
    // Model an env-derived var so `carries_user_data` is true —
    // otherwise the policy gate would auto-approve and every test
    // that checks deny/ignore/allow semantics would trivially
    // pass. Tests that specifically care about the
    // hardcoded-literal path build their `ResolvedVar` directly
    // with `VarValue::specified`.
    ProvenancedVar::new(
        ResolvedVar::resolve_with(name.into(), VarValue::Inherit, |_| Ok(value.to_string()))
            .unwrap(),
        source,
    )
}

fn pp(source_pattern: &str, dest: &str, prov: Source) -> ProvenancedPatch {
    ProvenancedPatch::new(
        Patch::new(source_pattern, PatchDest::try_new(dest).unwrap()),
        prov,
    )
}

/// The core of the daemon-resolves-inherited-vars fix: a project
/// `Inherit` var composed daemon-side must be shipped to the client
/// as an `Inherit` *spec*, never as a `Specified` carrying whatever
/// value the daemon's own environment held — and the client then
/// resolves it against the *user's* env.
#[test]
fn daemon_ships_inherit_spec_and_client_resolves_from_user_env() {
    // Daemon-side resolution uses `deferring_env`, so no host lookup
    // happens and the placeholder value is a discardable "".
    let env = deferring_env();
    let daemon = ResolvedVar::resolve_with("LANG".into(), VarValue::Inherit, &env).unwrap();
    let transform = contribution_to_pending(
        vec![ProvenancedVar::new(daemon, project_source())],
        vec![],
        vec![],
    );
    let wire = &transform.wire.vars[0];
    // Shipped as the spec, not the daemon's baked-in value.
    assert_eq!(wire.spec, crate::wire::primitives::WireVarSpec::Inherit);

    // The client resolves against the USER's env — not the daemon's.
    let user_env = |name: &str| {
        if name == "LANG" {
            Ok("en_US.UTF-8".to_string())
        } else {
            Err(std::env::VarError::NotPresent)
        }
    };
    let pending = PendingVar::from_wire(wire.clone(), &user_env).unwrap();
    assert_eq!(pending.provenanced().var().value(), "en_US.UTF-8");
    assert!(pending.provenanced().var().carries_user_data());
}

/// `InheritWithDefault` ships its default in the spec so the client
/// falls back correctly when the user's env is unset (and marks it
/// not-user-data), yet uses the user's value when present.
#[test]
fn daemon_ships_inherit_with_default_and_client_resolves_both_ways() {
    let env = deferring_env();
    let daemon =
        ResolvedVar::resolve_with("TZ".into(), VarValue::inherit_with_default("UTC"), &env)
            .unwrap();
    let transform = contribution_to_pending(
        vec![ProvenancedVar::new(daemon, project_source())],
        vec![],
        vec![],
    );
    let wire = &transform.wire.vars[0];
    assert_eq!(
        wire.spec,
        crate::wire::primitives::WireVarSpec::InheritWithDefault {
            default: "UTC".into()
        }
    );

    // User env unset → default, not user data.
    let miss = |_: &str| Err(std::env::VarError::NotPresent);
    let pending = PendingVar::from_wire(wire.clone(), &miss).unwrap();
    assert_eq!(pending.provenanced().var().value(), "UTC");
    assert!(!pending.provenanced().var().carries_user_data());

    // User env set → the user's value, marked as user data.
    let hit = |name: &str| {
        if name == "TZ" {
            Ok("America/New_York".to_string())
        } else {
            Err(std::env::VarError::NotPresent)
        }
    };
    let pending = PendingVar::from_wire(wire.clone(), &hit).unwrap();
    assert_eq!(pending.provenanced().var().value(), "America/New_York");
    assert!(pending.provenanced().var().carries_user_data());
}

type VarsPolicyMutator = Box<dyn Fn(&mut VarsPolicy)>;

struct ScriptedHook {
    var_responses: RefCell<Vec<HookResult<VarsPolicy>>>,
    var_mutate: RefCell<Vec<VarsPolicyMutator>>,
}

impl ScriptedHook {
    fn new(responses: Vec<HookResult<VarsPolicy>>) -> Self {
        Self {
            var_responses: RefCell::new(responses),
            var_mutate: RefCell::new(Vec::new()),
        }
    }
    fn with_mutator<F: Fn(&mut VarsPolicy) + 'static>(mut self, f: F) -> Self {
        self.var_mutate.get_mut().push(Box::new(f));
        self
    }
}

impl PolicyHooks for ScriptedHook {
    fn on_var_unapproved(
        &self,
        mut policy: VarsPolicy,
        _items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        let mutated = self
            .var_mutate
            .borrow_mut()
            .pop()
            .inspect(|m| m(&mut policy));
        let response = self
            .var_responses
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| panic!("ScriptedHook: ran out of queued var responses"));
        if mutated.is_some() {
            match response {
                HookResult::Decided {
                    decisions,
                    updated_policy: None,
                } => HookResult::decided_with_policy(decisions, policy),
                other => other,
            }
        } else {
            response
        }
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        _items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        panic!("patch hook not expected in these tests")
    }
}

/// Hook that panics on either domain. Used by tests asserting that
/// the hook MUST NOT be reached — typically because a bypass or
/// other short-circuit was supposed to fire first.
struct PanicHook;
impl PolicyHooks for PanicHook {
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
}

/// Hook that approves everything (`AllowOnce` for every item). Used
/// when the test cares about flow rather than hook semantics.
struct PassThroughHook;
impl PolicyHooks for PassThroughHook {
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

/// Build a `Patch` with a single-file source rooted at a tempdir.
fn single_file_patch(name: &str, dest: &str) -> (tempfile::TempDir, Patch) {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
    let file = root.join(name);
    std::fs::write(file.as_std_path(), "x").unwrap();
    let patch = Patch::new(file.as_str(), PatchDest::try_new(dest).unwrap());
    (tmp, patch)
}

// =================================================================
// `$LOADOUT_ROOT` anchoring
// =================================================================

/// Where a patch's `$LOADOUT_ROOT` resolves is decided per patch,
/// from the provenance it carries — not once for the whole batch.
mod loadout_root_anchoring {
    use super::*;

    fn loadouts_dir() -> paths::HostAbsPath {
        paths::HostAbsPath::try_new("/cfg/minimal/loadouts").unwrap()
    }

    fn rooted_patch(loadout: &str) -> ProvenancedPatch {
        ProvenancedPatch::new(
            Patch::new(
                "$LOADOUT_ROOT/conf.toml",
                PatchDest::try_new("conf.toml").unwrap(),
            ),
            Source::UserLoadout {
                name: loadout.into(),
            },
        )
    }

    /// Two loadouts declaring the identical pattern resolve to
    /// their own directories — this is what makes the reference
    /// mean "beside *me*" rather than "in the loadouts directory".
    #[test]
    fn each_patch_anchors_at_its_own_loadouts_subdirectory() {
        let dir = loadouts_dir();
        let expanded = expand_patch_sources(
            vec![rooted_patch("dev"), rooted_patch("ops")],
            &[],
            PatchAnchors::default().with_loadouts_dir(Some(&dir)),
            false,
        )
        .unwrap();
        assert_eq!(
            expanded[0].source.pattern(),
            "/cfg/minimal/loadouts/dev/conf.toml"
        );
        assert_eq!(
            expanded[1].source.pattern(),
            "/cfg/minimal/loadouts/ops/conf.toml"
        );
    }

    /// A project's patch has no loadout to be beside, even when a
    /// loadouts directory is in play for the same composition.
    #[test]
    fn a_non_loadout_patch_has_no_anchor() {
        let pp = ProvenancedPatch::new(
            Patch::new(
                "$LOADOUT_ROOT/conf.toml",
                PatchDest::try_new("conf.toml").unwrap(),
            ),
            project_source(),
        );
        // let-else rather than `unwrap_err`: the Ok side isn't
        // `Debug`, and printing an expanded patch set adds nothing
        // to the failure message anyway.
        let Err(err) = expand_patch_sources(
            vec![pp],
            &[],
            PatchAnchors::default().with_loadouts_dir(Some(&loadouts_dir())),
            false,
        ) else {
            panic!("a project patch must not resolve `$LOADOUT_ROOT`");
        };
        assert!(
            matches!(
                err,
                ComposeError::Expansion(
                    crate::core::expansion::ExpandError::LoadoutRootUnavailable { .. }
                )
            ),
            "got: {err:?}",
        );
    }

    /// A caller that never supplied a loadouts directory — the
    /// daemon-response path — can't anchor a loadout patch either,
    /// rather than guessing a directory.
    #[test]
    fn without_a_loadouts_dir_even_a_loadout_patch_has_no_anchor() {
        let Err(err) = expand_patch_sources(
            vec![rooted_patch("dev")],
            &[],
            PatchAnchors::default(),
            false,
        ) else {
            panic!("no loadouts dir means no anchor to resolve against");
        };
        assert!(
            matches!(
                err,
                ComposeError::Expansion(
                    crate::core::expansion::ExpandError::LoadoutRootUnavailable { .. }
                )
            ),
            "got: {err:?}",
        );
    }

    /// A loadout name that isn't a path component that stays put
    /// gets no anchor: the name is joined into a path that is then
    /// read from. `LoadoutName` already rejects these, but wire
    /// provenance carries an unvetted string.
    #[test]
    fn a_name_that_is_not_a_path_component_gets_no_anchor() {
        let Err(err) = expand_patch_sources(
            vec![rooted_patch("..")],
            &[],
            PatchAnchors::default().with_loadouts_dir(Some(&loadouts_dir())),
            false,
        ) else {
            panic!("`..` must not be joined into an anchor path");
        };
        assert!(
            matches!(
                err,
                ComposeError::Expansion(
                    crate::core::expansion::ExpandError::LoadoutRootUnavailable { .. }
                )
            ),
            "got: {err:?}",
        );
    }
}

// =================================================================
// Vars gating
// =================================================================

mod vars_gating {
    /// A batch holding both a denied name and an merely-unapproved one
    /// fails on the denial without the hook ever being consulted.
    ///
    /// `deny` is the emergency stop. Prompting about a neighbour first
    /// wastes the answer — and can persist a rule to `user_policy.toml`
    /// — for a composition that was never going to succeed. The
    /// hook here panics if called, so the order is enforced rather
    /// than described.
    #[test]
    fn a_denial_short_circuits_before_any_hook_runs() {
        use super::super::{ComposeError, gate_names};
        use crate::core::hooks::{HookResult, PolicyHooks, Unapproved};
        use crate::core::policy::{PatchesPolicy, VarsPolicy};
        use crate::core::source::Source;

        struct NeverAsked;
        impl PolicyHooks for NeverAsked {
            fn on_var_unapproved(
                &self,
                _p: VarsPolicy,
                items: &[Unapproved<'_, str>],
            ) -> HookResult<VarsPolicy> {
                panic!("a denial must stop the batch first; asked about {items:?}");
            }
            fn on_patch_unapproved(
                &self,
                _p: PatchesPolicy,
                _i: &[Unapproved<'_, camino::Utf8Path>],
            ) -> HookResult<PatchesPolicy> {
                unreachable!()
            }
        }

        let source = Source::Project {
            path: paths::HostPath::try_new(camino::Utf8PathBuf::from("/p")).unwrap(),
        };
        let policy = VarsPolicy::empty().try_with_deny(["DENIED"]).unwrap();
        // Sorted so the denied name is not simply first by luck.
        let items = [("ALSO_UNLISTED", &source), ("DENIED", &source)];

        let err = gate_names(&items, policy, Some(&NeverAsked))
            .expect_err("a denied name must fail the batch");
        assert!(
            matches!(&err, ComposeError::Denied { what, .. } if what == "DENIED"),
            "names the denied variable: {err:?}",
        );
    }

    use super::*;

    #[test]
    fn allow_passes_through_with_source_preserved() {
        let policy = VarsPolicy::empty().try_with_allow(["A_*"]).unwrap();
        let (out, _) = gate_vars(vec![pv("A_FOO")], policy, Some(&PanicHook)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].var().name(), "A_FOO");
        assert_eq!(out[0].source(), &project_source());
    }

    #[test]
    fn ignore_drops_silently() {
        let policy = VarsPolicy::empty().try_with_ignore(["_*"]).unwrap();
        let (out, _) = gate_vars(vec![pv("_TMP")], policy, Some(&PanicHook)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn deny_errors() {
        let policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
        let err = gate_vars(vec![pv("AWS_KEY")], policy, Some(&PanicHook)).unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    /// User-origin items are still subject to `deny` — the user
    /// is the authority for what's *in* their loadout, but a deny
    /// rule explicitly overrides that. `PanicHook` ensures the
    /// denial fires at Pass 1 without going through a prompt.
    #[test]
    fn user_loadout_honors_deny() {
        let policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
        let err = gate_vars(
            vec![pv_with("AWS_KEY", user_source())],
            policy,
            Some(&PanicHook),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    /// User-origin items bypass the `allow` requirement — no need
    /// to explicitly allow what's in your own loadout — and don't
    /// trigger a prompt. `PanicHook` proves the auto-allow path.
    #[test]
    fn user_loadout_bypasses_allow_requirement() {
        let policy = VarsPolicy::empty();
        let (out, _) = gate_vars(
            vec![pv_with("MY_FOO", user_source())],
            policy,
            Some(&PanicHook),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].var().name(), "MY_FOO");
    }

    #[test]
    fn user_loadout_still_honors_ignore() {
        let policy = VarsPolicy::empty().try_with_ignore(["_*"]).unwrap();
        let (out, _) = gate_vars(
            vec![pv_with("_TMP", user_source())],
            policy,
            Some(&PanicHook),
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn package_origin_still_denied() {
        let policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
        let pkg_pv = pv_with(
            "AWS_KEY",
            Source::Package {
                name: "evil-pkg".into(),
            },
        );
        let err = gate_vars(vec![pkg_pv], policy, Some(&PanicHook)).unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    #[test]
    fn hook_allow_once() {
        let policy = VarsPolicy::empty();
        let hook = ScriptedHook::new(vec![HookResult::decided(vec![ItemDecision::AllowOnce])]);
        let (out, _) = gate_vars(vec![pv("MY_FOO")], policy, Some(&hook)).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn hook_use_rule_without_mutation_errors_as_hook_contract() {
        let policy = VarsPolicy::empty();
        let hook = ScriptedHook::new(vec![HookResult::decided(vec![ItemDecision::UseRule])]);
        let err = gate_vars(vec![pv("MY_FOO")], policy, Some(&hook)).unwrap_err();
        assert!(
            matches!(err, ComposeError::HookContract { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn hook_abort_propagates() {
        let policy = VarsPolicy::empty();
        let hook = ScriptedHook::new(vec![HookResult::Abort]);
        let err = gate_vars(vec![pv("MY_FOO")], policy, Some(&hook)).unwrap_err();
        assert!(matches!(err, ComposeError::Aborted));
    }

    #[test]
    fn hook_decision_count_mismatch_errors() {
        let policy = VarsPolicy::empty();
        let hook = ScriptedHook::new(vec![HookResult::decided(vec![
            ItemDecision::AllowOnce,
            ItemDecision::AllowOnce,
        ])]);
        let err = gate_vars(vec![pv("MY_FOO")], policy, Some(&hook)).unwrap_err();
        assert!(
            matches!(err, ComposeError::HookContract { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn hook_mixed_batch_applies_decisions_in_order() {
        let policy = VarsPolicy::empty();
        let hook = ScriptedHook::new(vec![HookResult::decided(vec![
            ItemDecision::AllowOnce,
            ItemDecision::UseRule,
            ItemDecision::AllowOnce,
        ])])
        .with_mutator(|p| {
            *p = p.clone().try_with_allow(["MIDDLE_*"]).unwrap();
        });
        let (out, _) = gate_vars(
            vec![pv("FIRST"), pv("MIDDLE_OK"), pv("LAST")],
            policy,
            Some(&hook),
        )
        .unwrap();
        let names: Vec<_> = out.iter().map(|sv| sv.var().name()).collect();
        assert_eq!(names, ["FIRST", "MIDDLE_OK", "LAST"]);
    }

    /// A non-user-origin var that the policy can't auto-decide,
    /// fed into the hook-less path, surfaces as `HookRequired`.
    #[test]
    fn no_hook_with_unapproved_item_errors() {
        let policy = VarsPolicy::empty();
        let err = gate_vars(vec![pv("MY_FOO")], policy, None).unwrap_err();
        assert!(
            matches!(err, ComposeError::HookRequired { ref what, .. } if what == "MY_FOO"),
            "got: {err:?}",
        );
    }

    /// User-origin items in the hook-less path still work: with
    /// an empty policy, the allow step auto-passes and produces
    /// `Decided`, so the hook is never consulted.
    #[test]
    fn no_hook_with_user_origin_succeeds() {
        let policy = VarsPolicy::empty();
        let (out, _) = gate_vars(vec![pv_with("EDITOR", user_source())], policy, None).unwrap();
        assert_eq!(out.len(), 1);
    }
}

// =================================================================
// Patches gating
// =================================================================

mod patches_gating {
    use super::*;

    #[test]
    fn user_origin_single_file_short_circuits() {
        let (_tmp, patch) = single_file_patch("hello.txt", "config/hello.txt");
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty();
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].source(), &user_source());
    }

    #[test]
    fn project_origin_goes_through_prompt() {
        let (_tmp, patch) = single_file_patch("conf.toml", "etc/conf.toml");
        let pp = ProvenancedPatch::new(patch, project_source());
        let policy = PatchesPolicy::empty();
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PassThroughHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].source(), &project_source());
    }

    #[test]
    fn deny_via_policy_errors() {
        let (_tmp, patch) = single_file_patch("secret.pem", "config/x");
        let pp = ProvenancedPatch::new(patch, project_source());
        let policy = PatchesPolicy::empty().with_deny(["/**/*.pem"]);
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PassThroughHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    /// User-origin patches are still subject to `deny` — a deny
    /// rule overrides the user's own loadout declaration.
    #[test]
    fn user_loadout_honors_deny() {
        let (_tmp, patch) = single_file_patch("secret.pem", "config/x");
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty().with_deny(["/**/*.pem"]);
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    #[test]
    fn user_loadout_still_honors_ignore() {
        let (_tmp, patch) = single_file_patch("trash.bak", "config/x");
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty().with_ignore(["/**/*.bak"]);
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        assert!(resolved.is_empty());
    }

    /// Build a [`SessionVar`] for tests where the gating step expects
    /// a value to substitute into `$VAR` or `~/` references.
    fn home_var(value: &str) -> SessionVar {
        let resolved = ResolvedVar::resolve_with("HOME".into(), VarValue::specified(value), |_| {
            Err(std::env::VarError::NotPresent)
        })
        .unwrap();
        SessionVar::new(resolved, user_source())
    }

    #[test]
    fn multi_file_glob_fans_out_with_relative_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        std::fs::write(root.join("a.lua").as_std_path(), "a").unwrap();
        std::fs::create_dir_all(root.join("sub").as_std_path()).unwrap();
        std::fs::write(root.join("sub/b.lua").as_std_path(), "b").unwrap();
        std::fs::write(root.join("skip.txt").as_std_path(), "x").unwrap();

        let pattern = format!("{root}/**/*.lua");
        let patch = Patch::new(pattern, PatchDest::try_new("nvim").unwrap());
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty();
        let (mut resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        resolved.sort_by_key(|sp| sp.patch().destination().as_str().to_owned());
        let dests: Vec<_> = resolved
            .iter()
            .map(|sp| sp.patch().destination().as_str())
            .collect();
        assert_eq!(dests, ["nvim/a.lua", "nvim/sub/b.lua"]);
    }

    /// A patch whose walk root doesn't exist on the host is
    /// silently dropped with a `tracing::warn!`, not surfaced as
    /// [`ComposeError::PatchWalk`]. A user activating a loadout
    /// that opportunistically patches something absent (e.g. a
    /// missing dotfile tree) shouldn't have activation fail.
    #[test]
    fn missing_patch_source_is_dropped_not_error() {
        let patch = Patch::new(
            "/definitely/does/not/exist/*",
            PatchDest::try_new("x").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty();
        let (patches, _policy) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .expect("missing walk root should not error");
        assert!(
            patches.is_empty(),
            "missing source should yield no patches, got {patches:?}",
        );
    }

    /// A batch mixing missing and present patch sources keeps
    /// the present ones through and warn-drops the missing —
    /// one bad path doesn't sink the whole activation.
    #[test]
    fn missing_and_present_patches_partition_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        std::fs::write(root.join("real.txt").as_std_path(), "x").unwrap();
        let real_pattern = format!("{root}/real.txt");

        let present = ProvenancedPatch::new(
            Patch::new(&real_pattern, PatchDest::try_new("real.txt").unwrap()),
            user_source(),
        );
        let missing = ProvenancedPatch::new(
            Patch::new(
                "/definitely/does/not/exist/*",
                PatchDest::try_new("m").unwrap(),
            ),
            user_source(),
        );
        let policy = PatchesPolicy::empty();
        let (patches, _) = gate_patches(
            vec![present, missing],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .expect("mixed batch should not error");
        let dests: Vec<&str> = patches
            .iter()
            .map(|sp| sp.patch().destination().as_str())
            .collect();
        assert_eq!(dests, ["real.txt"]);
    }

    #[test]
    fn tilde_pattern_with_missing_home_var_errors() {
        let patch = Patch::new("~/dotfiles/conf", PatchDest::try_new("conf").unwrap());
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty();
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Expansion(crate::core::expansion::ExpandError::UndefinedVar { ref name })
                    if name == "HOME"
            ),
            "got: {err:?}",
        );
    }

    #[test]
    fn tilde_pattern_expands_with_home_session_var() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        std::fs::create_dir_all(root.join("dotfiles").as_std_path()).unwrap();
        std::fs::write(root.join("dotfiles/conf").as_std_path(), "x").unwrap();

        let patch = Patch::new("~/dotfiles/conf", PatchDest::try_new("conf").unwrap());
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty();
        let vars = [home_var(root.as_str())];
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &vars,
            PatchAnchors::default(),
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].patch().host_path().as_str(),
            root.join("dotfiles/conf").as_str(),
        );
    }

    #[test]
    fn policy_tilde_pattern_actually_denies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        std::fs::create_dir_all(root.join(".ssh").as_std_path()).unwrap();
        std::fs::write(root.join(".ssh/id_rsa").as_std_path(), "secret").unwrap();

        let patch = Patch::new(
            root.join(".ssh/id_rsa").as_str(),
            PatchDest::try_new("id_rsa").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, project_source());

        let policy = PatchesPolicy::empty().with_deny(["~/.ssh/**"]);
        let vars = [home_var(root.as_str())];

        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PassThroughHook),
            ComposeOptions::default(),
            &vars,
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    #[test]
    fn policy_tilde_pattern_without_home_var_errors() {
        let (_tmp, patch) = single_file_patch("conf.toml", "conf");
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty().with_deny(["~/.ssh/**"]);
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Expansion(crate::core::expansion::ExpandError::UndefinedVar { ref name })
                    if name == "HOME"
            ),
            "got: {err:?}",
        );
    }

    /// `~someuser/…` (per-user tilde) is rejected at expansion —
    /// only bare `~` and `~/…` are supported. Silent noop
    /// otherwise: the pattern would be literal and never match.
    #[test]
    fn user_prefixed_tilde_is_rejected() {
        let (_tmp, patch) = single_file_patch("conf.toml", "conf");
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty().with_deny(["~someuser/.ssh/**"]);
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Expansion(
                    crate::core::expansion::ExpandError::UnsupportedTildeUser { .. }
                )
            ),
            "got: {err:?}",
        );
    }

    #[test]
    fn returned_policy_preserves_raw_tilde_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        let file = root.join("hello.txt");
        std::fs::write(file.as_std_path(), "x").unwrap();

        let patch = Patch::new(file.as_str(), PatchDest::try_new("hello.txt").unwrap());
        let pp = ProvenancedPatch::new(patch, user_source());

        let policy = PatchesPolicy::empty().with_allow(["~/.config/**"]);
        let vars = [home_var(root.as_str())];

        let (_resolved, policy_out) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &vars,
            PatchAnchors::default(),
        )
        .unwrap();

        assert_eq!(policy_out.allow(), ["~/.config/**"]);
    }

    #[test]
    fn hook_added_tilde_rule_is_enforced_after_reexpansion() {
        struct TildeDenyAddingHook;
        impl PolicyHooks for TildeDenyAddingHook {
            fn on_var_unapproved(
                &self,
                _: VarsPolicy,
                items: &[Unapproved<'_, str>],
            ) -> HookResult<VarsPolicy> {
                HookResult::decided(vec![ItemDecision::UseRule; items.len()])
            }
            fn on_patch_unapproved(
                &self,
                policy: PatchesPolicy,
                items: &[Unapproved<'_, camino::Utf8Path>],
            ) -> HookResult<PatchesPolicy> {
                let updated = policy.with_deny(["~/*.pem"]);
                HookResult::decided_with_policy(vec![ItemDecision::UseRule; items.len()], updated)
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        let file = root.join("secret.pem");
        std::fs::write(file.as_std_path(), "x").unwrap();

        let patch = Patch::new(file.as_str(), PatchDest::try_new("secret.pem").unwrap());
        let pp = ProvenancedPatch::new(patch, project_source());

        let policy = PatchesPolicy::empty();
        let vars = [home_var(root.as_str())];

        let err = gate_patches(
            vec![pp],
            policy,
            Some(&TildeDenyAddingHook),
            ComposeOptions::default(),
            &vars,
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    #[test]
    fn hook_policy_referencing_unknown_var_errors_strictly() {
        struct UnknownVarHook;
        impl PolicyHooks for UnknownVarHook {
            fn on_var_unapproved(
                &self,
                _: VarsPolicy,
                items: &[Unapproved<'_, str>],
            ) -> HookResult<VarsPolicy> {
                HookResult::decided(vec![ItemDecision::UseRule; items.len()])
            }
            fn on_patch_unapproved(
                &self,
                policy: PatchesPolicy,
                items: &[Unapproved<'_, camino::Utf8Path>],
            ) -> HookResult<PatchesPolicy> {
                let updated = policy.with_deny(["$NOT_RESOLVED/*"]);
                HookResult::decided_with_policy(vec![ItemDecision::UseRule; items.len()], updated)
            }
        }
        let (_tmp, patch) = single_file_patch("conf.toml", "conf");
        let pp = ProvenancedPatch::new(patch, project_source());
        let policy = PatchesPolicy::empty();
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&UnknownVarHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Expansion(crate::core::expansion::ExpandError::UndefinedVar { ref name })
                    if name == "NOT_RESOLVED"
            ),
            "got: {err:?}",
        );
    }

    #[cfg(unix)]
    fn symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).expect("symlink");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_walk_root_yields_link_paths_under_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_root = Utf8Path::from_path(tmp.path()).unwrap();
        let real = tmp_root.join("real");
        std::fs::create_dir_all(real.as_std_path()).unwrap();
        std::fs::write(real.join("conf.toml").as_std_path(), "x").unwrap();
        let link = tmp_root.join("link");
        symlink(real.as_std_path(), link.as_std_path());

        let patch = Patch::new(
            format!("{link}/**/*.toml"),
            PatchDest::try_new("etc").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, user_source());
        let policy = PatchesPolicy::empty();
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions {
                follow_symlinks: true,
            },
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_denied_wins_over_link_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        let root = Utf8Path::from_path(&canonical).unwrap().to_path_buf();
        let allowed_dir = root.join("allowed_dir");
        let denied_dir = root.join("denied_dir");
        std::fs::create_dir_all(allowed_dir.as_std_path()).unwrap();
        std::fs::create_dir_all(denied_dir.as_std_path()).unwrap();
        let target_file = denied_dir.join("leak");
        std::fs::write(target_file.as_std_path(), "secret").unwrap();
        let link_file = allowed_dir.join("secret");
        symlink(target_file.as_std_path(), link_file.as_std_path());

        let patch = Patch::new(
            format!("{allowed_dir}/**"),
            PatchDest::try_new("etc").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, project_source());
        let policy = PatchesPolicy::empty().with_deny([format!("{denied_dir}/**")]);
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PassThroughHook),
            ComposeOptions {
                follow_symlinks: true,
            },
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    /// Mirror of the test above: the LINK path is denied while the
    /// TARGET it resolves to is allowed. This is the sole live-fire
    /// coverage of the link-path arm of the dual check at
    /// `policy.rs` `check()` — mutation testing (Kani PR #1217
    /// review) showed that deleting that arm passes the whole suite
    /// AND all lattice proofs: the proofs discharge the combine
    /// algebra, not the wiring that feeds it.
    #[cfg(unix)]
    #[test]
    fn symlink_link_denied_wins_over_allowed_target() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        let root = Utf8Path::from_path(&canonical).unwrap().to_path_buf();
        let allowed_dir = root.join("allowed_dir");
        let denied_dir = root.join("denied_dir");
        std::fs::create_dir_all(allowed_dir.as_std_path()).unwrap();
        std::fs::create_dir_all(denied_dir.as_std_path()).unwrap();
        let target_file = allowed_dir.join("innocent");
        std::fs::write(target_file.as_std_path(), "fine").unwrap();
        let link_file = denied_dir.join("route");
        symlink(target_file.as_std_path(), link_file.as_std_path());

        let patch = Patch::new(
            format!("{denied_dir}/**"),
            PatchDest::try_new("etc").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, project_source());
        let policy = PatchesPolicy::empty().with_deny([format!("{denied_dir}/**")]);
        let err = gate_patches(
            vec![pp],
            policy,
            Some(&PassThroughHook),
            ComposeOptions {
                follow_symlinks: true,
            },
            &[],
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn follow_symlinks_on_normal_file_uses_target_only() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        let root = Utf8Path::from_path(&canonical).unwrap().to_path_buf();
        std::fs::write(root.join("ok.txt").as_std_path(), "x").unwrap();
        let patch = Patch::new(
            format!("{root}/**/*.txt"),
            PatchDest::try_new("etc").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, project_source());
        let policy = PatchesPolicy::empty().with_allow([format!("{root}/**")]);
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions {
                follow_symlinks: true,
            },
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
    }

    /// Regression for the macOS-style symlinked walk-root prefix
    /// case (e.g. `/tmp` → `/private/tmp`). With
    /// `follow_symlinks: false` — the default — canonicalization
    /// must NOT happen, otherwise policy patterns written against
    /// the user-visible prefix mis-match the canonical target
    /// prefix and innocent files silently fall through to
    /// `NeedsApproval`.
    #[cfg(unix)]
    #[test]
    fn symlinked_prefix_in_default_mode_matches_link_form_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_root = Utf8Path::from_path(tmp.path()).unwrap();
        let real = tmp_root.join("real_dir");
        std::fs::create_dir_all(real.as_std_path()).unwrap();
        std::fs::write(real.join("conf.toml").as_std_path(), "x").unwrap();
        let link = tmp_root.join("link_dir");
        symlink(real.as_std_path(), link.as_std_path());

        let patch = Patch::new(
            format!("{link}/**/*.toml"),
            PatchDest::try_new("etc").unwrap(),
        );
        let pp = ProvenancedPatch::new(patch, project_source());

        let policy = PatchesPolicy::empty().with_allow([format!("{link}/**")]);
        let (resolved, _) = gate_patches(
            vec![pp],
            policy,
            Some(&PanicHook),
            ComposeOptions::default(),
            &[],
            PatchAnchors::default(),
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
    }
}

// =================================================================
// Display snapshots
// =================================================================

mod display_snapshots {
    use super::*;

    #[test]
    fn compose_error_denied() {
        let err = ComposeError::Denied {
            what: "AWS_KEY".into(),
            from: user_source(),
        };
        assert_eq!(
            err.to_string(),
            "policy denied `AWS_KEY` (from user loadout `test`)",
        );
    }

    #[test]
    fn compose_error_aborted() {
        assert_eq!(
            ComposeError::Aborted.to_string(),
            "user aborted session construction",
        );
    }

    #[test]
    fn source_variants() {
        assert_eq!(user_source().to_string(), "user loadout `test`");
        assert_eq!(project_source().to_string(), "project `/repo`");
        assert_eq!(
            Source::Package {
                name: "evil".into(),
            }
            .to_string(),
            "package `evil`",
        );
    }

    #[test]
    fn conflict_var_value_mismatch() {
        let c = Conflict::VarValueMismatch {
            name: "EDITOR".into(),
            disagreeing_values: vec![
                (
                    Source::Package {
                        name: "helix".into(),
                    },
                    "hx".into(),
                ),
                (Source::UserLoadout { name: "dev".into() }, "vim".into()),
            ],
        };
        assert_eq!(
            c.to_string(),
            "variable `EDITOR` set to conflicting values:\n  \
                 - \"hx\" (from package `helix`)\n  \
                 - \"vim\" (from user loadout `dev`)\n\
                 hint: add `EDITOR` to your policy's ignore list \
                 to drop all of these contributors",
        );
    }

    #[test]
    fn conflict_patch_source_mismatch() {
        let c = Conflict::PatchSourceMismatch {
            dest: paths::SandboxRelPath::try_new(".config/helix/themes").unwrap(),
            disagreeing_sources: vec![
                (
                    Source::Package {
                        name: "helix".into(),
                    },
                    "/usr/share/helix/themes/nord.toml".into(),
                ),
                (
                    Source::UserLoadout { name: "dev".into() },
                    "/home/u/dotfiles/themes/nord.toml".into(),
                ),
            ],
        };
        assert_eq!(
            c.to_string(),
            "patch destination `.config/helix/themes` has conflicting sources:\n  \
                 - \"/usr/share/helix/themes/nord.toml\" (from package `helix`)\n  \
                 - \"/home/u/dotfiles/themes/nord.toml\" (from user loadout `dev`)\n\
                 hint: add a pattern matching the conflicting source path(s) above \
                 to your patch policy's ignore list to drop both, \
                 or remove one of the contributors",
        );
    }

    #[test]
    fn compose_error_wraps_conflict_via_from() {
        let conflict = Conflict::VarValueMismatch {
            name: "EDITOR".into(),
            disagreeing_values: vec![
                (user_source(), "vim".into()),
                (
                    Source::Package {
                        name: "helix".into(),
                    },
                    "hx".into(),
                ),
            ],
        };
        // `#[from]` lets `?` propagate Conflict through ComposeError.
        let err: ComposeError = conflict.into();
        assert!(matches!(err, ComposeError::Conflict { .. }));
    }
}

// =================================================================
// Merge-time conflict detection helpers
// =================================================================

mod conflict_helpers {
    use super::*;

    // ---------------- check_var_mismatches ----------------

    #[test]
    fn vars_empty_is_ok() {
        let items: Vec<ProvenancedVar> = vec![];
        assert!(check_var_mismatches(&items, |v| v.var().name(), |v| v.var().value()).is_ok());
    }

    #[test]
    fn vars_distinct_names_ok() {
        let items = vec![
            pv_value("EDITOR", "hx", project_source()),
            pv_value("LANG", "C", user_source()),
        ];
        assert!(check_var_mismatches(&items, |v| v.var().name(), |v| v.var().value()).is_ok());
    }

    #[test]
    fn vars_same_name_same_value_ok() {
        // Two contributors agreeing on a var is harmless.
        let items = vec![
            pv_value("EDITOR", "hx", project_source()),
            pv_value("EDITOR", "hx", user_source()),
        ];
        assert!(check_var_mismatches(&items, |v| v.var().name(), |v| v.var().value()).is_ok());
    }

    #[test]
    fn vars_same_name_different_value_errors() {
        let items = vec![
            pv_value(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            ),
            pv_value("EDITOR", "vim", Source::UserLoadout { name: "dev".into() }),
        ];
        let err =
            check_var_mismatches(&items, |v| v.var().name(), |v| v.var().value()).unwrap_err();
        match err {
            Conflict::VarValueMismatch {
                name,
                disagreeing_values,
            } => {
                assert_eq!(name, "EDITOR");
                assert_eq!(disagreeing_values.len(), 2);
                let values: Vec<&str> =
                    disagreeing_values.iter().map(|(_, v)| v.as_str()).collect();
                assert_eq!(values, vec!["hx", "vim"]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn vars_conflict_keeps_all_contributors_under_that_name() {
        // Three contributors: two agree on "hx", one says "vim".
        // The conflict's `disagreeing_values` lists all three so the
        // user sees the full picture.
        let items = vec![
            pv_value(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            ),
            pv_value("EDITOR", "hx", user_source()),
            pv_value("LANG", "C", project_source()),
            pv_value("EDITOR", "vim", Source::UserLoadout { name: "dev".into() }),
        ];
        let err =
            check_var_mismatches(&items, |v| v.var().name(), |v| v.var().value()).unwrap_err();
        let Conflict::VarValueMismatch {
            disagreeing_values, ..
        } = err
        else {
            panic!("expected VarValueMismatch");
        };
        // Three EDITOR contributors; LANG excluded.
        assert_eq!(disagreeing_values.len(), 3);
    }

    // ---------------- check_patch_mismatches ----------------

    #[test]
    fn patches_distinct_dests_ok() {
        let items = vec![
            pp("/etc/foo", "config/foo", project_source()),
            pp("/etc/bar", "config/bar", user_source()),
        ];
        assert!(
            check_patch_mismatches(
                &items,
                |p| p.patch().dest().as_sandbox_path(),
                |p| p.patch().source(),
            )
            .is_ok()
        );
    }

    #[test]
    fn patches_same_dest_same_source_ok() {
        let items = vec![
            pp("/etc/foo", "config/foo", project_source()),
            pp("/etc/foo", "config/foo", user_source()),
        ];
        assert!(
            check_patch_mismatches(
                &items,
                |p| p.patch().dest().as_sandbox_path(),
                |p| p.patch().source(),
            )
            .is_ok()
        );
    }

    #[test]
    fn patches_same_dest_different_source_errors() {
        let items = vec![
            pp(
                "/usr/share/nord.toml",
                "config/themes",
                Source::Package {
                    name: "helix".into(),
                },
            ),
            pp(
                "/home/u/nord.toml",
                "config/themes",
                Source::UserLoadout { name: "dev".into() },
            ),
        ];
        let err = check_patch_mismatches(
            &items,
            |p| p.patch().dest().as_sandbox_path(),
            |p| p.patch().source(),
        )
        .unwrap_err();
        match err {
            Conflict::PatchSourceMismatch {
                dest,
                disagreeing_sources,
            } => {
                assert_eq!(dest.as_utf8_path().as_str(), "config/themes");
                assert_eq!(disagreeing_sources.len(), 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---------------- check_patch_prefix_collisions ----------------

    #[test]
    fn prefix_collision_sibling_dests_ok() {
        // Nothing overlaps: two files in the same dir don't
        // collide, they just coexist under `<home>/config/`.
        let items = vec![
            pp("/etc/foo", "config/foo", project_source()),
            pp("/etc/bar", "config/bar", user_source()),
        ];
        assert!(
            check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path()).is_ok()
        );
    }

    #[test]
    fn prefix_collision_same_dest_ok() {
        // Exact-equal destinations are the
        // `PatchSourceMismatch` case, not this one. This check
        // must not fire on them regardless of whether the
        // sources agree.
        let items = vec![
            pp("/etc/foo", "config/foo", project_source()),
            pp("/etc/foo", "config/foo", user_source()),
        ];
        assert!(
            check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path()).is_ok()
        );
    }

    #[test]
    fn prefix_collision_shared_string_prefix_ok() {
        // Component boundary matters: `foo` isn't a prefix of
        // `foobar` — those are just two independent files at the
        // same level.
        let items = vec![
            pp("/etc/foo", "foo", project_source()),
            pp("/etc/foobar", "foobar", user_source()),
        ];
        assert!(
            check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path()).is_ok()
        );
    }

    #[test]
    fn prefix_collision_nested_dests_errors() {
        // Concrete example: one contributor wants a file at
        // `foo`, another wants a file at `foo/bar`. Materialize
        // would fail on whichever ran second.
        let items = vec![
            pp("/etc/foo.txt", "foo", project_source()),
            pp(
                "/etc/bar.txt",
                "foo/bar",
                Source::UserLoadout { name: "dev".into() },
            ),
        ];
        let err = check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path())
            .unwrap_err();
        match err {
            Conflict::PatchDestPrefixCollision {
                shorter,
                longer,
                contributors,
            } => {
                assert_eq!(shorter.as_utf8_path().as_str(), "foo");
                assert_eq!(longer.as_utf8_path().as_str(), "foo/bar");
                assert_eq!(contributors.len(), 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn prefix_collision_input_order_independent() {
        // The check fires whichever order the two destinations
        // appear in the batch. Guards against a future
        // refactor that only compares "later against earlier".
        let a = pp("/etc/foo.txt", "foo", project_source());
        let b = pp(
            "/etc/bar.txt",
            "foo/bar",
            Source::UserLoadout { name: "dev".into() },
        );
        assert!(
            check_patch_prefix_collisions(&[a.clone(), b.clone()], |p| p
                .patch()
                .dest()
                .as_sandbox_path())
            .is_err()
        );
        assert!(
            check_patch_prefix_collisions(&[b, a], |p| p.patch().dest().as_sandbox_path()).is_err()
        );
    }

    // ---------------- dedupe_by_name ----------------

    #[test]
    fn dedupe_empty_is_noop() {
        let mut items: Vec<&str> = vec![];
        dedupe_by_name(&mut items, |s| s);
        assert!(items.is_empty());
    }

    #[test]
    fn dedupe_no_duplicates_unchanged() {
        let mut items = vec!["helix", "ripgrep", "fd"];
        dedupe_by_name(&mut items, |s| s);
        assert_eq!(items, vec!["helix", "ripgrep", "fd"]);
    }

    #[test]
    fn dedupe_drops_duplicates_keeping_first_occurrence() {
        let mut items = vec!["helix", "ripgrep", "helix", "fd", "ripgrep"];
        dedupe_by_name(&mut items, |s| s);
        assert_eq!(items, vec!["helix", "ripgrep", "fd"]);
    }

    /// Sanity check against the real caller shape: same-named
    /// packages from different sources collapse to the first
    /// occurrence (source provenance comes from that entry).
    #[test]
    fn dedupe_provenanced_packages_keeps_first_source() {
        let first = ProvenancedPackage::new("helix", project_source());
        let second = ProvenancedPackage::new("helix", Source::UserLoadout { name: "dev".into() });
        let third = ProvenancedPackage::new("ripgrep", user_source());
        let mut items = vec![first.clone(), second, third.clone()];
        dedupe_by_name(&mut items, ProvenancedPackage::package);
        // `second` was dropped; provenance on the surviving `helix`
        // entry is the first contributor's.
        assert_eq!(items, vec![first, third]);
    }
}

// =================================================================
// Contribution::merge
// =================================================================

mod merge {
    use super::*;
    use crate::core::lifecyclehook::{HookScript, LifecycleHook};

    fn pkg(name: &str, source: Source) -> ProvenancedPackage {
        ProvenancedPackage::new(name, source)
    }

    fn hook(body: &str, source: Source) -> ProvenancedHook {
        let lh = LifecycleHook::builder()
            .with_on_activate(HookScript::inline(body))
            .build()
            .expect("at least one callback set");
        ProvenancedHook::new(lh, source)
    }

    fn contribution_with(
        vars: Vec<ProvenancedVar>,
        patches: Vec<ProvenancedPatch>,
        packages: Vec<ProvenancedPackage>,
        hooks: Vec<ProvenancedHook>,
    ) -> Contribution {
        Contribution {
            vars,
            patches,
            packages,
            lifecycle_hooks: hooks,
        }
    }

    #[test]
    fn empty_merge_is_identity() {
        let mut left = Contribution::new();
        left.merge(Contribution::new()).unwrap();
        assert!(left.vars.is_empty());
        assert!(left.patches.is_empty());
        assert!(left.packages.is_empty());
        assert!(left.lifecycle_hooks.is_empty());
    }

    // ---------------- vars ----------------

    #[test]
    fn vars_distinct_names_merge_cleanly() {
        let mut left = contribution_with(
            vec![pv_value("EDITOR", "hx", project_source())],
            vec![],
            vec![],
            vec![],
        );
        let right = contribution_with(
            vec![pv_value("LANG", "C", user_source())],
            vec![],
            vec![],
            vec![],
        );
        left.merge(right).unwrap();
        assert_eq!(left.vars.len(), 2);
    }

    #[test]
    fn vars_same_name_same_value_both_kept() {
        // Two contributors agreeing on a var is not a conflict;
        // both entries survive (Source provenance is preserved).
        let mut left = contribution_with(
            vec![pv_value(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            vec![],
            vec![],
            vec![],
        );
        let right = contribution_with(
            vec![pv_value("EDITOR", "hx", user_source())],
            vec![],
            vec![],
            vec![],
        );
        left.merge(right).unwrap();
        assert_eq!(left.vars.len(), 2);
    }

    /// merge is now pure aggregation: disagreeing values land
    /// in `self.vars` and are detected later, post-gate. The
    /// merge itself succeeds.
    #[test]
    fn vars_same_name_different_value_no_longer_errors_at_merge() {
        let mut left = contribution_with(
            vec![pv_value(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            vec![],
            vec![],
            vec![],
        );
        let right = contribution_with(
            vec![pv_value(
                "EDITOR",
                "vim",
                Source::UserLoadout { name: "dev".into() },
            )],
            vec![],
            vec![],
            vec![],
        );
        left.merge(right).unwrap();
        assert_eq!(left.vars.len(), 2);
    }

    // ---------------- patches ----------------

    #[test]
    fn patches_distinct_dests_merge_cleanly() {
        let mut left = contribution_with(
            vec![],
            vec![pp("/etc/foo", "config/foo", project_source())],
            vec![],
            vec![],
        );
        let right = contribution_with(
            vec![],
            vec![pp("/etc/bar", "config/bar", user_source())],
            vec![],
            vec![],
        );
        left.merge(right).unwrap();
        assert_eq!(left.patches.len(), 2);
    }

    /// Same: patches with the same dest but different sources
    /// land in `self.patches`; conflict detection happens
    /// later, post-gate.
    #[test]
    fn patches_same_dest_different_source_no_longer_errors_at_merge() {
        let mut left = contribution_with(
            vec![],
            vec![pp(
                "/usr/share/nord.toml",
                "config/themes",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            vec![],
            vec![],
        );
        let right = contribution_with(
            vec![],
            vec![pp(
                "/home/u/nord.toml",
                "config/themes",
                Source::UserLoadout { name: "dev".into() },
            )],
            vec![],
            vec![],
        );
        left.merge(right).unwrap();
        assert_eq!(left.patches.len(), 2);
    }

    // ---------------- packages ----------------

    #[test]
    fn packages_dedupe_by_name_across_sides() {
        let mut left = contribution_with(
            vec![],
            vec![],
            vec![
                pkg("helix", project_source()),
                pkg("ripgrep", project_source()),
            ],
            vec![],
        );
        let right = contribution_with(
            vec![],
            vec![],
            vec![pkg("helix", user_source()), pkg("fd", user_source())],
            vec![],
        );
        left.merge(right).unwrap();
        let names: Vec<&str> = left
            .packages
            .iter()
            .map(ProvenancedPackage::package)
            .collect();
        // helix appears once (first-occurrence wins).
        assert_eq!(names, vec!["helix", "ripgrep", "fd"]);
    }

    // ---------------- hooks ----------------

    #[test]
    fn hooks_concatenate_unconditionally() {
        // Two identical hook scripts are both kept — hooks are
        // code that runs, no dedupe.
        let mut left = contribution_with(
            vec![],
            vec![],
            vec![],
            vec![hook("echo hi", project_source())],
        );
        let right = contribution_with(vec![], vec![], vec![], vec![hook("echo hi", user_source())]);
        left.merge(right).unwrap();
        assert_eq!(left.lifecycle_hooks.len(), 2);
    }

    // ---------------- hook ordering contract ----------------

    /// The composed hook list is project-first, loadouts-after, and
    /// the teardown view is its exact reverse.
    ///
    /// This is the property project maintainers depend on — set up
    /// before any developer's personal hooks, tear down after them —
    /// and it falls out of *how* a composition is assembled (daemon
    /// pass-through first, client contribution appended), so nothing
    /// but a test stops a future refactor of that assembly from
    /// silently inverting it.
    #[test]
    fn hooks_compose_project_first_and_tear_down_in_reverse() {
        use crate::wire::request::WireContribution;

        // Daemon side: the project's hooks are installed first.
        let mut composition = Composition::from_daemon_passthrough(
            Vec::new(),
            vec![hook("project", project_source())],
        );
        // Client side: the loadouts' hooks arrive already gated and
        // are appended.
        composition
            .extend_from_wire(WireContribution {
                lifecycle_hooks: vec![hook("loadout", user_source()).into()],
                ..Default::default()
            })
            .expect("appending a gated contribution");

        let setup: Vec<&Source> = composition
            .lifecycle_hooks()
            .iter()
            .map(Provenanced::source)
            .collect();
        assert_eq!(
            setup,
            vec![&project_source(), &user_source()],
            "setup order must be project, then loadouts",
        );

        let teardown: Vec<&Source> = composition
            .lifecycle_hooks_teardown()
            .map(Provenanced::source)
            .collect();
        assert_eq!(
            teardown,
            vec![&user_source(), &project_source()],
            "teardown order must be the exact reverse of setup",
        );
    }

    /// The teardown view is a pure reordering: same hooks, same
    /// count, nothing dropped. Guards against a future
    /// implementation that filters while reversing.
    #[test]
    fn teardown_view_is_a_pure_reversal() {
        let mut composition = Composition::from_daemon_passthrough(
            Vec::new(),
            vec![
                hook("a", project_source()),
                hook("b", user_source()),
                hook("c", user_source()),
            ],
        );
        // Touch `composition` mutably so the borrow shape matches
        // real use, then compare the two views.
        let forward: Vec<_> = composition.lifecycle_hooks().to_vec();
        let mut reversed: Vec<_> = composition.lifecycle_hooks_teardown().cloned().collect();
        assert_eq!(reversed.len(), forward.len());
        reversed.reverse();
        assert_eq!(reversed, forward);
        let _ = &mut composition;
    }

    // ---------------- package-supplied fs / user-data filter ----------------

    /// A package may not supply patches, nor vars that carry user
    /// data (env-inherited values). Both are dropped; a package's
    /// static var and every non-package item survive.
    #[test]
    fn package_supplied_patches_and_user_data_vars_are_dropped() {
        let pkg_src = || Source::Package { name: "go".into() };
        let mut c = Contribution::new();
        // Patches: one from a package (dropped), one from the project (kept).
        c.push_patch(pp("pkg/src", "etc/pkg.conf", pkg_src()));
        c.push_patch(pp("proj/src", "etc/proj.conf", project_source()));
        // Vars: package env-inherited (dropped), package static (kept),
        // project env-inherited (kept).
        c.push_var(ProvenancedVar::new(
            ResolvedVar::from_env_value("SECRET".into(), "s".into()),
            pkg_src(),
        ));
        c.push_var(ProvenancedVar::new(
            ResolvedVar::from_literal("GOFLAGS".into(), "-mod=mod".into()),
            pkg_src(),
        ));
        c.push_var(pv_value("EDITOR", "hx", project_source()));

        c.drop_package_supplied_patches_and_user_data_vars();

        // Only the project patch survives.
        assert_eq!(c.patches().len(), 1);
        assert!(matches!(c.patches()[0].source(), Source::Project { .. }));

        // The package's env-inherited var is gone; its static var and
        // the project var remain.
        let names: Vec<&str> = c.vars().iter().map(|v| v.var().name()).collect();
        assert_eq!(names.len(), 2);
        assert!(
            names.contains(&"GOFLAGS"),
            "package static var kept: {names:?}"
        );
        assert!(names.contains(&"EDITOR"), "project var kept: {names:?}");
        assert!(
            !names.contains(&"SECRET"),
            "package user-data var dropped: {names:?}"
        );
    }

    /// An item requested by a package *and* another source still
    /// composes in: dropping the package's own entry leaves the
    /// project/loadout entry (same patch dest / var name) intact,
    /// because vars and patches are never deduped across sources.
    #[test]
    fn item_from_package_and_another_source_survives_via_the_other_source() {
        let pkg_src = || Source::Package { name: "go".into() };
        let mut c = Contribution::new();
        // Same patch destination from a package and the project.
        c.push_patch(pp("pkg/src", "etc/shared.conf", pkg_src()));
        c.push_patch(pp("proj/src", "etc/shared.conf", project_source()));
        // Same env-inherited var name from a package and a loadout.
        c.push_var(ProvenancedVar::new(
            ResolvedVar::from_env_value("TOKEN".into(), "t".into()),
            pkg_src(),
        ));
        c.push_var(pv_value("TOKEN", "t", user_source()));

        c.drop_package_supplied_patches_and_user_data_vars();

        // The shared patch destination still composes — via the project.
        assert_eq!(c.patches().len(), 1);
        assert!(matches!(c.patches()[0].source(), Source::Project { .. }));
        // The shared var still composes — via the loadout.
        assert_eq!(c.vars().len(), 1);
        assert!(matches!(c.vars()[0].source(), Source::UserLoadout { .. }));
        assert_eq!(c.vars()[0].var().name(), "TOKEN");
    }

    // ---------------- pure aggregation (no conflict check) ----------------

    /// Multiple disagreeing contributions across every domain are
    /// all accumulated by merge — no error. Conflict detection
    /// is the job of [`compose_contribution`], post-gate.
    #[test]
    fn merge_aggregates_disagreement_without_erroring() {
        let mut left = contribution_with(
            vec![pv_value("EDITOR", "hx", project_source())],
            vec![pp("/etc/a/nord", "config/themes", project_source())],
            vec![pkg("helix", project_source())],
            vec![hook("echo a", project_source())],
        );
        let right = contribution_with(
            vec![pv_value("EDITOR", "vim", user_source())],
            vec![pp("/etc/b/nord", "config/themes", user_source())],
            vec![pkg("fd", user_source())],
            vec![hook("echo b", user_source())],
        );
        left.merge(right).unwrap();
        // Both disagreeing values survive; conflict will surface
        // later (post-gate) in `compose_contribution`.
        assert_eq!(left.vars.len(), 2);
        assert_eq!(left.patches.len(), 2);
    }
}

// =================================================================
// compose_contribution — post-gate conflict detection
// =================================================================

mod compose_conflicts {
    use super::*;
    use crate::core::hooks::PolicyHooks;

    struct PanicHooks;
    impl PolicyHooks for PanicHooks {
        fn on_var_unapproved(
            &self,
            _: VarsPolicy,
            _: &[crate::core::hooks::Unapproved<'_, str>],
        ) -> crate::core::hooks::HookResult<VarsPolicy> {
            panic!("hook should not have been invoked")
        }
        fn on_patch_unapproved(
            &self,
            _: PatchesPolicy,
            _: &[crate::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> crate::core::hooks::HookResult<PatchesPolicy> {
            panic!("hook should not have been invoked")
        }
    }

    /// Two contributors disagreeing on the same var name surface
    /// post-gate as `ComposeError::Conflict { VarValueMismatch }`.
    #[test]
    fn post_gate_var_disagreement_errors() {
        let mut contribution = Contribution::new();
        // Both contributors are user-loadout origin so the gate
        // auto-allows them; both reach the conflict check.
        contribution.push_var(pv_value(
            "EDITOR",
            "hx",
            Source::UserLoadout {
                name: "first".into(),
            },
        ));
        contribution.push_var(pv_value(
            "EDITOR",
            "vim",
            Source::UserLoadout {
                name: "second".into(),
            },
        ));
        let policy = UserPolicy::empty();
        let err = compose_contribution(
            contribution,
            &[],
            policy,
            Some(&PanicHooks),
            ComposeOptions::default(),
            PatchAnchors::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Conflict {
                    source: Conflict::VarValueMismatch { ref name, .. }
                } if name == "EDITOR"
            ),
            "got: {err:?}",
        );
    }

    /// Documented mitigation: adding the var to the `ignore`
    /// list drops the conflicting contributors during the gate,
    /// so the post-gate check has nothing to compare and the
    /// composition succeeds with no `EDITOR` set.
    #[test]
    fn ignore_policy_drops_conflicting_contributors_before_check() {
        let mut contribution = Contribution::new();
        contribution.push_var(pv_value(
            "EDITOR",
            "hx",
            Source::UserLoadout {
                name: "first".into(),
            },
        ));
        contribution.push_var(pv_value(
            "EDITOR",
            "vim",
            Source::UserLoadout {
                name: "second".into(),
            },
        ));
        let policy =
            UserPolicy::empty().with_vars(VarsPolicy::empty().try_with_ignore(["EDITOR"]).unwrap());
        let (composition, _policy) = compose_contribution(
            contribution,
            &[],
            policy,
            Some(&PanicHooks),
            ComposeOptions::default(),
            PatchAnchors::default(),
        )
        .unwrap();
        assert!(
            composition
                .vars()
                .iter()
                .all(|v| v.var().name() != "EDITOR"),
            "EDITOR should have been ignored",
        );
    }
}

// =================================================================
// Composition::extend_from_wire
// =================================================================

mod extend_from_wire {
    use super::*;
    use crate::wire::primitives::{
        WireLifecycleHook, WireOrientation, WirePackageRef, WireProvenancedHook, WireResolvedPatch,
        WireResolvedVar, WireSessionPatch, WireSessionVar, WireSource,
    };
    use crate::wire::request::WireContribution;

    // ---------------- helpers ----------------

    fn dev_loadout() -> WireSource {
        WireSource::UserLoadout { name: "dev".into() }
    }

    fn wire_var(name: &str, value: &str) -> WireSessionVar {
        WireSessionVar {
            var: WireResolvedVar {
                name: name.into(),
                value: value.into(),
                carries_user_data: true,
            },
            source: dev_loadout(),
        }
    }

    fn wire_patch(host: &str, dest: &str) -> WireSessionPatch {
        WireSessionPatch {
            patch: WireResolvedPatch {
                host_path: paths::HostAbsPath::try_new(host).unwrap(),
                destination: paths::SandboxRelPath::try_new(dest).unwrap(),
            },
            source: dev_loadout(),
        }
    }

    fn session_var(name: &str, value: &str, source: Source) -> SessionVar {
        SessionVar::new(
            ResolvedVar::resolve_with(name.into(), VarValue::specified(value), |_| {
                Err(std::env::VarError::NotPresent)
            })
            .unwrap(),
            source,
        )
    }

    fn session_patch(host: &str, dest: &str, source: Source) -> SessionPatch {
        SessionPatch {
            patch: ResolvedPatch::new(
                paths::HostAbsPath::try_new(host).unwrap(),
                paths::SandboxRelPath::try_new(dest).unwrap(),
            ),
            source,
        }
    }

    fn composition_with(vars: Vec<SessionVar>, patches: Vec<SessionPatch>) -> Composition {
        Composition {
            vars,
            patches,
            packages: Vec::new(),
            lifecycle_hooks: Vec::new(),
            orientation: Orientation::default(),
        }
    }

    fn wire_with(vars: Vec<WireSessionVar>, patches: Vec<WireSessionPatch>) -> WireContribution {
        WireContribution {
            vars,
            patches,
            requested_packages: vec![],
            lifecycle_hooks: vec![],
            orientation: WireOrientation::default(),
        }
    }

    /// A wire contribution carrying a malformed lifecycle hook (all
    /// three callbacks empty) must error without partially extending
    /// the [`Composition`]. The vars, patches, packages, and any
    /// well-formed hooks in the same wire payload must not appear
    /// in the [`Composition`] after the failed call.
    #[test]
    fn malformed_lifecycle_hook_leaves_composition_untouched() {
        let wire = WireContribution {
            vars: vec![WireSessionVar {
                var: WireResolvedVar {
                    name: "EDITOR".into(),
                    value: "hx".into(),
                    carries_user_data: true,
                },
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            patches: vec![],
            requested_packages: vec![WirePackageRef {
                name: "helix".into(),
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            // The empty hook fails the TryFrom<WireLifecycleHook>
            // conversion — at least one callback must be set.
            lifecycle_hooks: vec![WireProvenancedHook {
                hook: WireLifecycleHook::default(),
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            orientation: WireOrientation::default(),
        };

        let before = Composition::default();
        let mut after = before.clone();
        let err = after.extend_from_wire(wire).unwrap_err();
        assert!(
            matches!(err, ComposeError::InvalidWireItem { .. }),
            "got: {err:?}",
        );
        assert_eq!(after, before, "Composition mutated despite error");
    }

    // ---------------- cross-process conflict detection ----------------

    /// Daemon-side `EDITOR=hx` meets a wire `EDITOR=hx` from the
    /// client. Same value → no conflict; both entries survive.
    #[test]
    fn same_var_same_value_across_boundary_keeps_both() {
        let mut composition = composition_with(
            vec![session_var(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            vec![],
        );
        let wire = wire_with(vec![wire_var("EDITOR", "hx")], vec![]);
        composition.extend_from_wire(wire).unwrap();
        assert_eq!(composition.vars.len(), 2);
    }

    /// Patch-side parity for `same_var_same_value_across_boundary_keeps_both`:
    /// same dest + same `host_path` on both sides → no conflict,
    /// both entries survive.
    #[test]
    fn same_patch_same_source_across_boundary_keeps_both() {
        let mut composition = composition_with(
            vec![],
            vec![session_patch(
                "/usr/share/nord.toml",
                "config/themes",
                Source::Package {
                    name: "helix".into(),
                },
            )],
        );
        let wire = wire_with(
            vec![],
            vec![wire_patch("/usr/share/nord.toml", "config/themes")],
        );
        composition.extend_from_wire(wire).unwrap();
        assert_eq!(composition.patches.len(), 2);
    }

    /// A `WireContribution` carrying two vars with the same name
    /// and different values trips the conflict check even with no
    /// daemon-side contribution. The check runs over the chained
    /// iterator, so wire-vs-wire disagreement is caught.
    #[test]
    fn wire_self_var_conflict_is_caught() {
        let mut composition = Composition::default();
        let snapshot = composition.clone();
        let wire = wire_with(
            vec![wire_var("EDITOR", "hx"), wire_var("EDITOR", "vim")],
            vec![],
        );
        let err = composition.extend_from_wire(wire).unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Conflict {
                    source: Conflict::VarValueMismatch { .. }
                }
            ),
            "got: {err:?}",
        );
        assert_eq!(composition, snapshot);
    }

    /// Daemon `EDITOR=hx` vs wire `EDITOR=vim` → `Conflict::VarValueMismatch`,
    /// wrapped in `ComposeError::Conflict`.
    #[test]
    fn var_value_mismatch_across_boundary_errors_atomically() {
        let mut composition = composition_with(
            vec![session_var(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            vec![],
        );
        let snapshot = composition.clone();
        // Wire also carries a hook + package that would normally
        // land — none of them should appear after the failed call.
        let wire = WireContribution {
            vars: vec![wire_var("EDITOR", "vim")],
            patches: vec![],
            requested_packages: vec![WirePackageRef {
                name: "ripgrep".into(),
                source: dev_loadout(),
            }],
            lifecycle_hooks: vec![],
            orientation: WireOrientation::default(),
        };
        let err = composition.extend_from_wire(wire).unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Conflict {
                    source: Conflict::VarValueMismatch { ref name, .. }
                } if name == "EDITOR"
            ),
            "got: {err:?}",
        );
        // No partial mutation: vars, packages, hooks all unchanged.
        assert_eq!(composition, snapshot);
    }

    /// Patch dest collision across the boundary → `Conflict::PatchSourceMismatch`.
    /// Var check passes but patch check fails — vars must NOT have
    /// been pre-extended.
    #[test]
    fn patch_source_mismatch_after_var_check_passes_still_atomic() {
        let mut composition = composition_with(
            vec![session_var(
                "EDITOR",
                "hx",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            vec![session_patch(
                "/usr/share/nord.toml",
                "config/themes",
                Source::Package {
                    name: "helix".into(),
                },
            )],
        );
        let snapshot = composition.clone();
        let wire = wire_with(
            // Distinct name → var check passes.
            vec![wire_var("LANG", "C")],
            // Same dest, different host_path → patch check fails.
            vec![wire_patch("/home/u/nord.toml", "config/themes")],
        );
        let err = composition.extend_from_wire(wire).unwrap_err();
        assert!(
            matches!(
                err,
                ComposeError::Conflict {
                    source: Conflict::PatchSourceMismatch { .. }
                }
            ),
            "got: {err:?}",
        );
        // Crucially: vars were NOT pre-extended despite passing
        // their own check.
        assert_eq!(composition, snapshot);
    }

    /// Same package on both sides → one entry post-merge.
    #[test]
    fn packages_dedupe_across_boundary() {
        let mut composition = Composition {
            vars: vec![],
            patches: vec![],
            packages: vec![ProvenancedPackage::new(
                "helix",
                Source::Package {
                    name: "helix".into(),
                },
            )],
            lifecycle_hooks: vec![],
            orientation: Orientation::default(),
        };
        let wire = WireContribution {
            vars: vec![],
            patches: vec![],
            requested_packages: vec![
                WirePackageRef {
                    name: "helix".into(),
                    source: dev_loadout(),
                },
                WirePackageRef {
                    name: "ripgrep".into(),
                    source: dev_loadout(),
                },
            ],
            lifecycle_hooks: vec![],
            orientation: WireOrientation::default(),
        };
        composition.extend_from_wire(wire).unwrap();
        let names: Vec<&str> = composition
            .packages
            .iter()
            .map(ProvenancedPackage::package)
            .collect();
        // helix appears once (daemon side wins); ripgrep added.
        assert_eq!(names, vec!["helix", "ripgrep"]);
    }
}
