//! Integration tests for untrusted loadouts on the client side:
//! a [`Loadout`] marked [`Loadout::untrusted`] composes like any other,
//! except that the user policy gates it the way it gates a project —
//! its vars, patches, and lifecycle hooks must match an `allow` rule or
//! be approved by a [`PolicyHooks`] prompt.

use std::cell::RefCell;
use std::collections::HashMap;

use boxes::client::composer::UserComposer;
use boxes::core::compose::{ComposeError, ComposeOptions, StoredEnv};
use boxes::core::decision::ItemDecision;
use boxes::core::hooks::{HookResult, PolicyHooks, Unapproved};
use boxes::core::loadout::Loadout;
use boxes::core::policy::{HooksPolicy, PatchesPolicy, UserPolicy, VarsPolicy};
use boxes::core::source::Source;
use boxes::wire::primitives::WireSource;
use camino::{Utf8Path, Utf8PathBuf};

// =====================================================================
// Support
// =====================================================================

fn pinned_env(pairs: &[(&str, &str)]) -> StoredEnv {
    let owned: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Box::new(move |name: &str| {
        owned
            .get(name)
            .cloned()
            .ok_or(std::env::VarError::NotPresent)
    })
}

/// The untrusted loadout directory the tests pretend `ci` was read from.
const CI_DIR: &str = "/cfg/minimal/loadouts-untrusted/ci";

/// A loadout named `ci`, parsed from `body`, marked untrusted.
fn untrusted(body: &str) -> Loadout {
    untrusted_named("ci", body)
}

/// A loadout named `name`, parsed from `body`, marked untrusted as if
/// read from `/cfg/minimal/loadouts-untrusted/<name>`.
fn untrusted_named(name: &str, body: &str) -> Loadout {
    let loadout: Loadout = toml::from_str(&format!("name = \"{name}\"\n{body}")).unwrap();
    loadout.untrusted(
        paths::HostAbsPath::try_new(format!("/cfg/minimal/loadouts-untrusted/{name}")).unwrap(),
    )
}

/// `policy` with `names` allow-listed as vars, so an untrusted loadout's
/// literals pass the var gate and a test reaches what it is about.
fn allowing_vars(policy: UserPolicy, names: &[&str]) -> UserPolicy {
    policy.with_vars(
        VarsPolicy::empty()
            .try_with_allow(names.iter().copied())
            .unwrap(),
    )
}

/// A trusted loadout named `name`, parsed from `body`.
fn trusted_named(name: &str, body: &str) -> Loadout {
    toml::from_str(&format!("name = \"{name}\"\n{body}")).unwrap()
}

/// A `PolicyHooks` that answers every item with one fixed decision and
/// records what it was asked about, per domain.
struct Scripted {
    decision: ItemDecision,
    vars: RefCell<Vec<(String, Source)>>,
    /// The value each asked-about var would set, when its source set it.
    var_values: RefCell<Vec<Option<String>>>,
    patches: RefCell<Vec<(Utf8PathBuf, Source)>>,
    hooks: RefCell<Vec<(Utf8PathBuf, Source)>>,
}

impl Scripted {
    fn answering(decision: ItemDecision) -> Self {
        Self {
            decision,
            vars: RefCell::default(),
            var_values: RefCell::default(),
            patches: RefCell::default(),
            hooks: RefCell::default(),
        }
    }
}

impl PolicyHooks for Scripted {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        for item in items {
            self.vars
                .borrow_mut()
                .push((item.item().to_owned(), item.source().clone()));
            self.var_values
                .borrow_mut()
                .push(item.value().map(str::to_owned));
        }
        HookResult::decided(vec![self.decision; items.len()])
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        items: &[Unapproved<'_, Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        for item in items {
            self.patches
                .borrow_mut()
                .push((item.item().to_owned(), item.source().clone()));
        }
        HookResult::decided(vec![self.decision; items.len()])
    }

    fn on_hook_unapproved(
        &self,
        _policy: HooksPolicy,
        items: &[Unapproved<'_, Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        for item in items {
            self.hooks
                .borrow_mut()
                .push((item.item().to_owned(), item.source().clone()));
        }
        HookResult::decided(vec![self.decision; items.len()])
    }
}

const INHERITED_VAR: &str = r"
[vars]
GITHUB_TOKEN = { inherit = true }
";

const HOOK: &str = r#"
[[lifecycle_hooks]]
on_activate = { type = "inline", value = "echo hi" }
"#;

// =====================================================================
// Provenance
// =====================================================================

/// Everything an untrusted loadout contributes carries the untrusted
/// provenance, directory included, all the way onto the wire.
#[test]
fn untrusted_items_carry_untrusted_provenance_onto_the_wire() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer
        .add(untrusted("packages = [\"helix\"]\n[vars]\nLANG = \"C\"\n"))
        .unwrap();
    let (wire, _) = composer
        .compose(
            allowing_vars(UserPolicy::empty(), &["LANG"]),
            ComposeOptions::default(),
        )
        .unwrap();
    let expected = WireSource::UntrustedLoadout {
        name: "ci".into(),
        dir: paths::HostPath::try_new(CI_DIR).unwrap(),
    };
    assert_eq!(wire.vars[0].source, expected);
    assert_eq!(wire.requested_packages[0].source, expected);
}

// =====================================================================
// Vars
// =====================================================================

/// The control: the same inherited var from a trusted loadout needs no
/// `allow` rule.
#[test]
fn trusted_inherited_var_needs_no_allow_rule() {
    let loadout: Loadout = toml::from_str(&format!("name = \"ci\"\n{INHERITED_VAR}")).unwrap();
    let mut composer = UserComposer::new().with_env(pinned_env(&[("GITHUB_TOKEN", "t")]));
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();
    assert_eq!(wire.vars.len(), 1);
}

/// An untrusted loadout's inherited var does not auto-pass: with no
/// rule and nothing to ask, the composition fails rather than letting
/// the value through.
#[test]
fn untrusted_inherited_var_without_allow_cannot_compose_unasked() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[("GITHUB_TOKEN", "t")]));
    composer.add(untrusted(INHERITED_VAR)).unwrap();
    let err = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap_err();
    assert!(
        matches!(err, ComposeError::HookRequired { ref what, .. } if what == "GITHUB_TOKEN"),
        "got: {err:?}",
    );
}

/// An `allow` rule lets an untrusted loadout's var through, as it does a
/// project's.
#[test]
fn untrusted_inherited_var_passes_an_allow_rule() {
    let policy = UserPolicy::empty().with_vars(
        VarsPolicy::empty()
            .try_with_allow(["GITHUB_TOKEN"])
            .unwrap(),
    );
    let mut composer = UserComposer::new().with_env(pinned_env(&[("GITHUB_TOKEN", "t")]));
    composer.add(untrusted(INHERITED_VAR)).unwrap();
    let (wire, _) = composer.compose(policy, ComposeOptions::default()).unwrap();
    assert_eq!(wire.vars.len(), 1);
    assert_eq!(wire.vars[0].var.value, "t");
}

/// With no rule, the prompt is asked — about the var, naming the
/// untrusted loadout — and its answer decides.
#[test]
fn untrusted_inherited_var_is_put_to_the_prompt() {
    for (decision, kept) in [(ItemDecision::AllowOnce, 1), (ItemDecision::IgnoreOnce, 0)] {
        let hooks = Scripted::answering(decision);
        let mut composer = UserComposer::new().with_env(pinned_env(&[("GITHUB_TOKEN", "t")]));
        composer.add(untrusted(INHERITED_VAR)).unwrap();
        let (wire, _) = composer
            .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
            .unwrap();
        assert_eq!(wire.vars.len(), kept, "{decision:?}");
        let asked = hooks.vars.borrow();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, "GITHUB_TOKEN");
        assert!(
            matches!(&asked[0].1, Source::UntrustedLoadout { name, .. } if name == "ci"),
            "got: {:?}",
            asked[0].1,
        );
    }
}

/// Unlike a project's, an untrusted loadout's literal is gated: its
/// value is what runs code (`BASH_ENV`, `PATH`). With nothing to ask it
/// fails; asked, the prompt is shown the value it would set.
#[test]
fn untrusted_literal_var_is_gated_and_shows_its_value() {
    let body = "[vars]\nBASH_ENV = \"/tmp/payload\"\n";
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(body)).unwrap();
    let err = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap_err();
    assert!(
        matches!(err, ComposeError::HookRequired { ref what, .. } if what == "BASH_ENV"),
        "got: {err:?}",
    );

    for (decision, kept) in [(ItemDecision::AllowOnce, 1), (ItemDecision::IgnoreOnce, 0)] {
        let hooks = Scripted::answering(decision);
        let mut composer = UserComposer::new().with_env(pinned_env(&[]));
        composer.add(untrusted(body)).unwrap();
        let (wire, _) = composer
            .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
            .unwrap();
        assert_eq!(wire.vars.len(), kept, "{decision:?}");
        assert_eq!(
            *hooks.var_values.borrow(),
            [Some("/tmp/payload".to_owned())]
        );
    }

    // An `allow` rule on the name lets it through without asking.
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(body)).unwrap();
    let (wire, _) = composer
        .compose(
            allowing_vars(UserPolicy::empty(), &["BASH_ENV"]),
            ComposeOptions::default(),
        )
        .unwrap();
    assert_eq!(wire.vars.len(), 1);
}

/// An inherited var that fell back to its default is gated too, with
/// the default as its value; one that read the environment shows none.
#[test]
fn untrusted_defaulted_var_is_gated_with_its_default() {
    let body = "[vars]\nPAGER = { inherit = true, default = \"less\" }\n";
    for (env, value) in [
        (&[][..], Some("less".to_owned())),
        (&[("PAGER", "more")][..], None),
    ] {
        let hooks = Scripted::answering(ItemDecision::AllowOnce);
        let mut composer = UserComposer::new().with_env(pinned_env(env));
        composer.add(untrusted(body)).unwrap();
        composer
            .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
            .unwrap();
        assert_eq!(*hooks.var_values.borrow(), [value]);
    }
}

/// A trusted loadout's literal is still not gated.
#[test]
fn trusted_literal_var_is_not_gated() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer
        .add(trusted_named("dev", "[vars]\nBASH_ENV = \"/x\"\n"))
        .unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();
    assert_eq!(wire.vars.len(), 1);
}

// =====================================================================
// Patches
// =====================================================================

/// An untrusted loadout's patch needs an `allow` rule on its source path
/// or an approval; a trusted loadout's identical patch needs neither.
#[test]
fn untrusted_patch_is_gated_by_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    let file = root.join("netrc");
    std::fs::write(file.as_std_path(), "machine example\n").unwrap();
    let body = format!("[[patches]]\ndest = \".netrc\"\nsource = \"{file}\"\n");

    // Trusted: passes without a rule.
    let trusted: Loadout = toml::from_str(&format!("name = \"ci\"\n{body}")).unwrap();
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(trusted).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();
    assert_eq!(wire.patches.len(), 1);

    // Untrusted, no rule: the prompt is asked about the file.
    let hooks = Scripted::answering(ItemDecision::IgnoreOnce);
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(&body)).unwrap();
    let (wire, _) = composer
        .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
        .unwrap();
    assert!(
        wire.patches.is_empty(),
        "expected empty, got {:?}",
        wire.patches
    );
    assert_eq!(hooks.patches.borrow().len(), 1);

    // Untrusted, allow-listed: passes without asking.
    let policy =
        UserPolicy::empty().with_patches(PatchesPolicy::empty().with_allow([format!("{root}/**")]));
    let hooks = Scripted::answering(ItemDecision::IgnoreOnce);
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(&body)).unwrap();
    let (wire, _) = composer
        .compose_with_hooks(policy, ComposeOptions::default(), &hooks)
        .unwrap();
    assert_eq!(wire.patches.len(), 1);
    assert!(
        hooks.patches.borrow().is_empty(),
        "expected empty, got {:?}",
        hooks.patches.borrow()
    );
}

// =====================================================================
// Lifecycle hooks
// =====================================================================

/// A trusted loadout's hooks pass with no rule and nothing to ask.
#[test]
fn trusted_hooks_pass_without_a_rule() {
    let loadout: Loadout = toml::from_str(&format!("name = \"ci\"\n{HOOK}")).unwrap();
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();
    assert_eq!(wire.lifecycle_hooks.len(), 1);
}

/// An untrusted loadout's hooks are put to the prompt once, by the
/// loadout's own directory — the path a permanent approval would record
/// — and its answer decides them as a set.
#[test]
fn untrusted_hooks_are_asked_about_once_by_loadout_dir() {
    let two_hooks = format!("{HOOK}{HOOK}");
    for (decision, kept) in [(ItemDecision::AllowOnce, 2), (ItemDecision::IgnoreOnce, 0)] {
        let hooks = Scripted::answering(decision);
        let mut composer = UserComposer::new().with_env(pinned_env(&[]));
        composer.add(untrusted(&two_hooks)).unwrap();
        let (wire, _) = composer
            .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
            .unwrap();
        assert_eq!(wire.lifecycle_hooks.len(), kept, "{decision:?}");
        let asked = hooks.hooks.borrow();
        assert_eq!(asked.len(), 1, "one prompt per loadout, not per hook");
        assert_eq!(asked[0].0, CI_DIR);
    }
}

/// `allow` and `deny` rules on the loadout's directory decide its hooks
/// without a prompt, as they do a project's by its root.
#[test]
fn untrusted_hooks_follow_rules_on_the_loadout_dir() {
    let hooks = Scripted::answering(ItemDecision::IgnoreOnce);
    let policy =
        UserPolicy::empty().with_hooks(HooksPolicy::empty().with_allow(["/cfg/minimal/**"]));
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(HOOK)).unwrap();
    let (wire, _) = composer
        .compose_with_hooks(policy, ComposeOptions::default(), &hooks)
        .unwrap();
    assert_eq!(wire.lifecycle_hooks.len(), 1);
    assert!(
        hooks.hooks.borrow().is_empty(),
        "expected empty, got {:?}",
        hooks.hooks.borrow()
    );

    let policy = UserPolicy::empty().with_hooks(HooksPolicy::empty().with_deny([CI_DIR]));
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(HOOK)).unwrap();
    let err = composer
        .compose_with_hooks(policy, ComposeOptions::default(), &hooks)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ComposeError::Denied {
                from: Source::UntrustedLoadout { .. },
                ..
            }
        ),
        "got: {err:?}",
    );
}

/// With nothing to ask, an untrusted loadout's undecided hooks fail the
/// composition rather than running unapproved.
#[test]
fn untrusted_hooks_cannot_compose_unasked() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(HOOK)).unwrap();
    let err = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap_err();
    assert!(
        matches!(err, ComposeError::HookRequired { .. }),
        "got: {err:?}"
    );
}

// =====================================================================
// Policy expansion
// =====================================================================

/// An untrusted loadout's own `HOME` does not move the policy's `~/`:
/// the `deny` still expands against the real home and still matches.
/// Were its `HOME` honoured, the rule would expand under
/// `/nonexistent` and the key would fall through to a prompt.
#[test]
fn untrusted_home_cannot_defuse_a_tilde_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    std::fs::create_dir_all(home.join(".ssh").as_std_path()).unwrap();
    let key = home.join(".ssh/id_ed25519");
    std::fs::write(key.as_std_path(), "secret\n").unwrap();
    let body = format!(
        "[vars]\nHOME = \"/nonexistent\"\n\
         [[patches]]\ndest = \".ssh/id_ed25519\"\nsource = \"{key}\"\n"
    );
    let policy = allowing_vars(
        UserPolicy::empty().with_patches(PatchesPolicy::empty().with_deny(["~/.ssh/**"])),
        &["HOME"],
    );
    let mut composer = UserComposer::new().with_env(pinned_env(&[("HOME", home.as_str())]));
    composer.add(untrusted(&body)).unwrap();
    let err = composer
        .compose(policy, ComposeOptions::default())
        .unwrap_err();
    assert!(
        matches!(
            err,
            ComposeError::Denied {
                from: Source::UntrustedLoadout { .. },
                ..
            }
        ),
        "got: {err:?}",
    );
}

/// A policy pattern naming a var that only the untrusted loadout
/// defines fails to expand rather than expanding to whatever the
/// loadout chose, so the loadout cannot write its own `allow` rule.
#[test]
fn untrusted_var_cannot_satisfy_a_policy_pattern() {
    let body = format!("[vars]\nTEAM_DIR = \"{CI_DIR}\"\n{HOOK}");
    let policy = allowing_vars(
        UserPolicy::empty().with_hooks(HooksPolicy::empty().with_allow(["$TEAM_DIR"])),
        &["TEAM_DIR"],
    );
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(&body)).unwrap();
    let err = composer
        .compose(policy, ComposeOptions::default())
        .unwrap_err();
    assert!(
        matches!(
            err,
            ComposeError::Expansion(boxes::core::expansion::ExpandError::UndefinedVar { ref name })
                if name == "TEAM_DIR"
        ),
        "the loadout's own var must not allow its hooks; got: {err:?}",
    );
}

// =====================================================================
// Lifecycle hooks: grouping and rules chosen at the prompt
// =====================================================================

/// Answers every hook prompt with `UseRule`, having added each asked-about
/// root to the policy's `allow` — what "allow permanently" does. The
/// gate must then re-check against the amended policy and find it allowed.
struct AllowByRule;

impl PolicyHooks for AllowByRule {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        _items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        HookResult::Abort
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        _items: &[Unapproved<'_, Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        HookResult::Abort
    }

    fn on_hook_unapproved(
        &self,
        policy: HooksPolicy,
        items: &[Unapproved<'_, Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        let allow: Vec<String> = policy
            .allow()
            .iter()
            .cloned()
            .chain(items.iter().map(|i| i.item().to_string()))
            .collect();
        HookResult::decided_with_policy(
            vec![ItemDecision::UseRule; items.len()],
            policy.with_allow(allow),
        )
    }
}

/// `UseRule` re-checks the hook against the policy as the prompt amended
/// it: the added `allow` rule keeps the hook, and comes back in the
/// returned policy for the caller to save.
#[test]
fn untrusted_hooks_use_the_rule_chosen_at_the_prompt() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(HOOK)).unwrap();
    let (wire, policy) = composer
        .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &AllowByRule)
        .unwrap();
    assert_eq!(wire.lifecycle_hooks.len(), 1);
    assert_eq!(policy.hooks().allow(), [CI_DIR]);
}

/// A trusted and an untrusted loadout's hooks in one composition: only
/// the untrusted one is asked about, and refusing it drops only its hook.
#[test]
fn trusted_and_untrusted_hooks_are_gated_independently() {
    let hooks = Scripted::answering(ItemDecision::IgnoreOnce);
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(trusted_named("dev", HOOK)).unwrap();
    composer.add(untrusted(HOOK)).unwrap();
    let (wire, _) = composer
        .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
        .unwrap();
    assert_eq!(wire.lifecycle_hooks.len(), 1);
    assert_eq!(
        wire.lifecycle_hooks[0].source,
        WireSource::UserLoadout { name: "dev".into() },
    );
    let asked = hooks.hooks.borrow();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, CI_DIR);
}

/// Two untrusted loadouts are two sources: each is asked about once, by
/// its own directory, and a rule on one directory decides only that
/// loadout's hooks.
#[test]
fn each_untrusted_loadout_is_asked_about_by_its_own_dir() {
    let hooks = Scripted::answering(ItemDecision::AllowOnce);
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted_named("ci", HOOK)).unwrap();
    composer.add(untrusted_named("lint", HOOK)).unwrap();
    let (wire, _) = composer
        .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &hooks)
        .unwrap();
    assert_eq!(wire.lifecycle_hooks.len(), 2);
    let asked: Vec<Utf8PathBuf> = hooks
        .hooks
        .borrow()
        .iter()
        .map(|(p, _)| p.clone())
        .collect();
    assert_eq!(
        asked,
        [
            Utf8PathBuf::from("/cfg/minimal/loadouts-untrusted/ci"),
            Utf8PathBuf::from("/cfg/minimal/loadouts-untrusted/lint"),
        ],
    );

    // An `ignore` on `ci` alone: `lint` is still asked about and kept.
    let hooks = Scripted::answering(ItemDecision::AllowOnce);
    let policy = UserPolicy::empty().with_hooks(HooksPolicy::empty().with_ignore([CI_DIR]));
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted_named("ci", HOOK)).unwrap();
    composer.add(untrusted_named("lint", HOOK)).unwrap();
    let (wire, _) = composer
        .compose_with_hooks(policy, ComposeOptions::default(), &hooks)
        .unwrap();
    assert_eq!(wire.lifecycle_hooks.len(), 1);
    assert!(
        matches!(
            &wire.lifecycle_hooks[0].source,
            WireSource::UntrustedLoadout { name, .. } if name == "lint"
        ),
        "got: {:?}",
        wire.lifecycle_hooks[0].source,
    );
    assert_eq!(hooks.hooks.borrow().len(), 1);
}

// =====================================================================
// Patch sources: an untrusted loadout's vars reach only its own
// =====================================================================

/// An untrusted loadout's literal `HOME` does not move a trusted
/// loadout's `~/` patch source. Were it honoured, the trusted patch —
/// which no policy gates — would be read from wherever the untrusted
/// loadout pointed, with no prompt.
#[test]
fn untrusted_home_cannot_redirect_a_trusted_patch() {
    let real = tempfile::tempdir().unwrap();
    let real_home = Utf8Path::from_path(real.path()).unwrap();
    std::fs::write(real_home.join("dotfile").as_std_path(), "real\n").unwrap();
    let decoy = tempfile::tempdir().unwrap();
    let decoy_home = Utf8Path::from_path(decoy.path()).unwrap();
    std::fs::write(decoy_home.join("dotfile").as_std_path(), "decoy\n").unwrap();

    let mut composer = UserComposer::new().with_env(pinned_env(&[("HOME", real_home.as_str())]));
    composer
        .add(trusted_named(
            "dev",
            "[[patches]]\ndest = \".dotfile\"\nsource = \"~/dotfile\"\n",
        ))
        .unwrap();
    composer
        .add(untrusted(&format!("[vars]\nHOME = \"{decoy_home}\"\n")))
        .unwrap();
    let (wire, _) = composer
        .compose(
            allowing_vars(UserPolicy::empty(), &["HOME"]),
            ComposeOptions::default(),
        )
        .unwrap();
    assert_eq!(wire.patches.len(), 1);
    assert_eq!(
        wire.patches[0].patch.host_path.as_str(),
        real_home.join("dotfile").as_str(),
    );
}

/// A trusted patch source naming a var only an untrusted loadout
/// defines fails to expand rather than taking the untrusted value.
#[test]
fn untrusted_var_cannot_feed_a_trusted_patch_source() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer
        .add(trusted_named(
            "dev",
            "[[patches]]\ndest = \".x\"\nsource = \"$UT_DIR/x\"\n",
        ))
        .unwrap();
    composer
        .add(untrusted("[vars]\nUT_DIR = \"/etc\"\n"))
        .unwrap();
    let err = composer
        .compose(
            allowing_vars(UserPolicy::empty(), &["UT_DIR"]),
            ComposeOptions::default(),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            ComposeError::Expansion(boxes::core::expansion::ExpandError::UndefinedVar { ref name })
                if name == "UT_DIR"
        ),
        "got: {err:?}",
    );
}

/// An untrusted loadout's own patch may still use its own vars; its
/// patch is then gated by the path it expanded to.
#[test]
fn untrusted_patch_source_sees_its_own_vars() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    std::fs::write(root.join("x").as_std_path(), "x\n").unwrap();
    let body = format!(
        "patches = [{{ dest = \".x\", source = \"$UT_DIR/x\" }}]\n[vars]\nUT_DIR = \"{root}\"\n"
    );
    let policy = allowing_vars(
        UserPolicy::empty().with_patches(PatchesPolicy::empty().with_allow([format!("{root}/**")])),
        &["UT_DIR"],
    );
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(&body)).unwrap();
    let (wire, _) = composer.compose(policy, ComposeOptions::default()).unwrap();
    assert_eq!(wire.patches.len(), 1);
}

/// An untrusted loadout's patch may also use a trusted loadout's var.
#[test]
fn untrusted_patch_source_sees_trusted_vars() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    std::fs::write(root.join("x").as_std_path(), "x\n").unwrap();
    let policy =
        UserPolicy::empty().with_patches(PatchesPolicy::empty().with_allow([format!("{root}/**")]));
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer
        .add(trusted_named(
            "dev",
            &format!("[vars]\nSHARED_DIR = \"{root}\"\n"),
        ))
        .unwrap();
    composer
        .add(untrusted(
            "patches = [{ dest = \".x\", source = \"$SHARED_DIR/x\" }]\n",
        ))
        .unwrap();
    let (wire, _) = composer.compose(policy, ComposeOptions::default()).unwrap();
    assert_eq!(wire.patches.len(), 1);
}

/// Answers every hook prompt "deny permanently": adds the root to the
/// policy's `deny` and answers `UseRule`, as the interactive prompt does.
struct DenyByRule;

impl PolicyHooks for DenyByRule {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        _items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        HookResult::Abort
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        _items: &[Unapproved<'_, Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        HookResult::Abort
    }

    fn on_hook_unapproved(
        &self,
        policy: HooksPolicy,
        items: &[Unapproved<'_, Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        let deny: Vec<String> = items.iter().map(|i| i.item().to_string()).collect();
        HookResult::decided_with_policy(
            vec![ItemDecision::UseRule; items.len()],
            policy.with_deny(deny),
        )
    }
}

/// A deny chosen at the prompt fails the composition, as a deny rule
/// does: `ignore` is the way to skip a source's hooks and carry on.
#[test]
fn untrusted_hooks_denied_at_the_prompt_abort() {
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(untrusted(HOOK)).unwrap();
    let err = composer
        .compose_with_hooks(UserPolicy::empty(), ComposeOptions::default(), &DenyByRule)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ComposeError::Denied {
                from: Source::UntrustedLoadout { .. },
                ..
            }
        ),
        "got: {err:?}",
    );
}
