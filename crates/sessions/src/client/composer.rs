//! Client-side composer: gathers a user's loadouts, runs them through
//! their policy, and emits a wire contribution to ship to the daemon.

use crate::core::compose::{
    Composable, ComposeError, ComposeOptions, Composition, Contribution, Error, StoredEnv,
    compose_contribution, default_env,
};
use crate::core::loadout::Loadout;
use crate::core::policy::UserPolicy;
use crate::wire::request::WireContribution;

/// Accumulator for a user's loadouts, composed into a
/// [`WireContribution`] by [`Self::compose`].
///
/// User-origin items always reach a `Decided` outcome under
/// [`UserPolicy`] (the allow step auto-passes for them; `ignore`
/// and `deny` still apply), so the compose pass needs no
/// [`PolicyHooks`] — nothing here can land in a "needs approval"
/// state.
///
/// [`PolicyHooks`]: crate::core::hooks::PolicyHooks
pub struct UserComposer {
    contribution: Contribution,
    /// Names of every loadout already accepted via [`Self::add`].
    /// Duplicates are rejected up-front: `Loadout::follow_symlinks`
    /// is now stamped onto each patch's [`ProvenancedPatch`] and
    /// keyed by loadout name in the [`Source::UserLoadout`]
    /// provenance, so two loadouts sharing a name would produce
    /// patches that couldn't be attributed unambiguously.
    ///
    /// [`Source::UserLoadout`]: crate::core::source::Source::UserLoadout
    seen_names: std::collections::HashSet<crate::core::loadout::LoadoutName>,
    env: StoredEnv,
}

impl core::fmt::Debug for UserComposer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserComposer")
            .field("contribution", &self.contribution)
            .field("seen_names", &self.seen_names)
            .field("env", &"<closure>")
            .finish()
    }
}

impl Default for UserComposer {
    fn default() -> Self {
        Self::new()
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UserComposer>();
};

impl UserComposer {
    /// Construct an empty composer with the default env lookup
    /// ([`std::env::var`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            contribution: Contribution::new(),
            seen_names: std::collections::HashSet::new(),
            env: default_env(),
        }
    }

    /// Replace the env lookup. Useful for tests that want to pin env
    /// behavior without touching the process environment.
    #[must_use]
    pub fn with_env(mut self, env: StoredEnv) -> Self {
        self.env = env;
        self
    }

    /// Add a [`Loadout`] to this composer.
    ///
    /// # Errors
    ///
    /// Returns any error the loadout surfaces while resolving inherit
    /// or `InheritWithDefault` variables against `env`.
    pub fn add(&mut self, loadout: Loadout) -> Result<(), Error> {
        // Loadout names must be unique within a composer instance.
        // Two loadouts sharing a name would produce patches under the
        // same `Source::UserLoadout { name }`, and their
        // `follow_symlinks` overrides — stamped onto each patch's
        // `ProvenancedPatch` at contribute time — couldn't be
        // attributed unambiguously downstream.
        if self.seen_names.contains(loadout.name()) {
            return Err(Error::DuplicateLoadout {
                name: loadout.name().as_ref().to_string(),
            });
        }
        let name = loadout.name().clone();
        let incoming = loadout.contribute(&*self.env)?;
        // `merge` is internally atomic — on `Err`, `self.contribution`
        // is untouched.
        self.contribution.merge(incoming)?;
        self.seen_names.insert(name);
        Ok(())
    }

    /// Add every [`Loadout`] in `items` in order. Stops at the
    /// first failure.
    ///
    /// # Errors
    ///
    /// Returns the first [`Error`] surfaced by any loadout.
    pub fn add_all<I: IntoIterator<Item = Loadout>>(&mut self, items: I) -> Result<(), Error> {
        for loadout in items {
            self.add(loadout)?;
        }
        Ok(())
    }

    /// Compose every accumulated loadout against `policy` and emit
    /// the wire form ready to ship to the daemon.
    ///
    /// This composer only accepts loadouts via [`Self::add`], so every
    /// item carries `Source::UserLoadout`: the policy's allow step
    /// auto-passes, but `deny` and `ignore` still apply (so a user
    /// loadout entry matching a deny rule is rejected, and a match
    /// on ignore is silently dropped).
    ///
    /// # Errors
    ///
    /// See [`ComposeError`]. The hookless path returns
    /// [`ComposeError::HookRequired`] if a `Loadout::contribute` impl
    /// ever produces a non-user-origin item — a contributor bug, since
    /// loadouts must tag everything `Source::UserLoadout`.
    pub fn compose(
        self,
        policy: UserPolicy,
        options: ComposeOptions,
    ) -> Result<WireContribution, ComposeError> {
        // Tilde fallback comes from the user's env on the client side
        // (this is the user's own process environment, so it's the
        // right HOME to use when the loadout doesn't declare one).
        let home_fallback = (*self.env)("HOME").ok();
        let (composition, _final_policy) = compose_contribution(
            self.contribution,
            &[],
            policy,
            None,
            options,
            home_fallback.as_deref(),
        )?;
        Ok(composition_to_wire(composition))
    }
}

fn composition_to_wire(composition: Composition) -> WireContribution {
    let (vars, patches, packages, lifecycle_hooks) = composition.into_parts();
    WireContribution {
        vars: vars.into_iter().map(Into::into).collect(),
        patches: patches.into_iter().map(Into::into).collect(),
        lifecycle_hooks: lifecycle_hooks.into_iter().map(Into::into).collect(),
        requested_packages: packages.into_iter().map(Into::into).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::compose::Composable;
    use crate::core::lifecyclehook::{HookScript, LifecycleHook};
    use crate::core::loadout::LoadoutName;
    use crate::core::policy::VarsPolicy;
    use crate::core::primitives::{Patch, PatchDest, StrictVarName, VarValue};

    fn loadout_named(name: &str) -> Loadout {
        Loadout::new(LoadoutName::try_new(name).unwrap())
    }

    /// User-origin vars survive into the wire form with their resolved
    /// values intact.
    #[test]
    fn vars_serialize_into_wire_form() {
        let mut composer = UserComposer::new();
        composer
            .add(loadout_named("dev").with_var(
                StrictVarName::try_new("EDITOR").unwrap(),
                VarValue::specified("hx"),
            ))
            .unwrap();
        let wire = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert_eq!(wire.vars.len(), 1);
        assert_eq!(wire.vars[0].var.name, "EDITOR");
        assert_eq!(wire.vars[0].var.value, "hx");
        assert!(matches!(
            wire.vars[0].source,
            crate::wire::primitives::WireSource::UserLoadout { ref name } if name == "dev"
        ));
    }

    /// User policy's `ignore` rule still applies on the client-side
    /// path — matching vars are dropped before they hit the wire.
    #[test]
    fn ignore_filters_user_vars() {
        let policy =
            UserPolicy::empty().with_vars(VarsPolicy::empty().try_with_ignore(["_*"]).unwrap());
        let mut composer = UserComposer::new();
        composer
            .add(
                loadout_named("dev")
                    .with_var(
                        StrictVarName::try_new("_TMP").unwrap(),
                        VarValue::specified("x"),
                    )
                    .with_var(
                        StrictVarName::try_new("EDITOR").unwrap(),
                        VarValue::specified("hx"),
                    ),
            )
            .unwrap();
        let wire = composer.compose(policy, ComposeOptions::default()).unwrap();
        assert_eq!(wire.vars.len(), 1);
        assert_eq!(wire.vars[0].var.name, "EDITOR");
    }

    /// Packages and lifecycle hooks pass through unchanged.
    #[test]
    fn packages_and_hooks_pass_through() {
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::inline("echo hi"))
            .build()
            .unwrap();
        let mut composer = UserComposer::new();
        composer
            .add(
                loadout_named("dev")
                    .with_package("helix")
                    .with_lifecycle_hook(hook),
            )
            .unwrap();
        let wire = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert_eq!(wire.requested_packages.len(), 1);
        assert_eq!(wire.requested_packages[0].name, "helix");
        assert_eq!(wire.lifecycle_hooks.len(), 1);
    }

    /// Adding two loadouts with the same name is rejected. This is
    /// the invariant that lets each patch's `follow_symlinks`
    /// override be attributed unambiguously to its source loadout.
    #[test]
    fn add_rejects_duplicate_loadout_names() {
        let l1 = loadout_named("dev");
        let l2 = loadout_named("dev");
        let mut composer = UserComposer::new();
        composer.add(l1).unwrap();
        let err = composer.add(l2).unwrap_err();
        assert!(
            matches!(err, Error::DuplicateLoadout { ref name } if name == "dev"),
            "got: {err:?}",
        );
    }

    /// Per-loadout `follow_symlinks` is stamped onto every patch the
    /// loadout contributes; a loadout that doesn't set it leaves
    /// patches with `follow_symlinks = None`, which falls through to
    /// the compose default at expand time.
    #[test]
    fn per_loadout_follow_symlinks_stamps_onto_contributed_patches() {
        use crate::core::primitives::{Patch, PatchDest};

        let patch = Patch::new("/tmp/whatever", PatchDest::try_new("etc/whatever").unwrap());
        let opted_in = loadout_named("follow")
            .with_patch(patch.clone())
            .with_follow_symlinks(true);
        let inherit = loadout_named("inherit").with_patch(patch);

        let contrib_in = opted_in
            .contribute(&|_| Err(std::env::VarError::NotPresent))
            .unwrap();
        assert_eq!(contrib_in.patches.len(), 1);
        assert_eq!(contrib_in.patches[0].follow_symlinks(), Some(true));

        let contrib_none = inherit
            .contribute(&|_| Err(std::env::VarError::NotPresent))
            .unwrap();
        assert_eq!(contrib_none.patches.len(), 1);
        assert_eq!(contrib_none.patches[0].follow_symlinks(), None);
    }

    /// `add_all` runs a sequence of loadouts. Multiple loadouts
    /// accumulate independently.
    #[test]
    fn add_all_runs_a_sequence_of_loadouts() {
        let l1 = loadout_named("a").with_var(
            StrictVarName::try_new("EDITOR").unwrap(),
            VarValue::specified("hx"),
        );
        let l2 = loadout_named("b").with_var(
            StrictVarName::try_new("LANG").unwrap(),
            VarValue::specified("C"),
        );
        let mut composer = UserComposer::new();
        composer.add_all([l1, l2]).unwrap();
        let wire = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert_eq!(wire.vars.len(), 2);
    }

    /// `with_env` lets tests pin env behavior without touching the
    /// process environment. The provided closure resolves `LANG`
    /// when a loadout's var is `inherit = true`.
    #[test]
    fn with_env_overrides_lookup_for_inheriting_vars() {
        let loadout = loadout_named("dev")
            .with_var(StrictVarName::try_new("LANG").unwrap(), VarValue::Inherit);
        let mut composer = UserComposer::new().with_env(Box::new(|name| {
            if name == "LANG" {
                Ok("en_US.UTF-8".into())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        }));
        composer.add(loadout).unwrap();
        let wire = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert_eq!(wire.vars.len(), 1);
        assert_eq!(wire.vars[0].var.name, "LANG");
        assert_eq!(wire.vars[0].var.value, "en_US.UTF-8");
    }

    /// End-to-end: a loadout with vars, patches, packages, and a
    /// hook contributes all four kinds.
    #[test]
    fn loadout_contributes_all_four_kinds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let file = root.join("conf.toml");
        std::fs::write(file.as_std_path(), "x").unwrap();
        let patch = Patch::new(file.as_str(), PatchDest::try_new("etc/conf.toml").unwrap());

        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::inline("echo hi"))
            .build()
            .unwrap();

        let loadout = loadout_named("dev")
            .with_var(
                StrictVarName::try_new("EDITOR").unwrap(),
                VarValue::specified("hx"),
            )
            .with_package("helix")
            .with_patch(patch)
            .with_lifecycle_hook(hook);

        let mut composer = UserComposer::new();
        composer.add(loadout).unwrap();
        let wire = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert_eq!(wire.vars.len(), 1);
        assert_eq!(wire.patches.len(), 1);
        assert_eq!(wire.requested_packages.len(), 1);
        assert_eq!(wire.lifecycle_hooks.len(), 1);
    }
}
