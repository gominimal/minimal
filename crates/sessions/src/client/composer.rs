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
    env: StoredEnv,
}

impl core::fmt::Debug for UserComposer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserComposer")
            .field("contribution", &self.contribution)
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
        let incoming = loadout.contribute(&*self.env)?;
        // Merge on a clone so a `Conflict` leaves `self.contribution`
        // untouched. Today `Conflict` is uninhabited so the clone is
        // unused on the error path; it becomes load-bearing when
        // conflict-detection variants land.
        let merged = self.contribution.clone().merge(incoming)?;
        self.contribution = merged;
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
