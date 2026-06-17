//! Daemon-side composer: takes the client's wire contribution, gathers
//! project and package contributions, and produces a final
//! [`Composition`].

use crate::core::compose::{
    Composable, ComposeError, ComposeOptions, Composition, Contribution, Error, StoredEnv,
    compose_contribution, default_env,
};
use crate::core::policy::UserPolicy;
use crate::wire::request::WireContribution;

/// Accumulator for daemon-side contributions (project + packages),
/// joined with the client's already-gated wire contribution.
///
/// [`Self::compose`] runs the daemon-side items through the policy
/// and then appends the client's pre-gated items verbatim. The daemon
/// does *not* run policy hooks — items the policy can't auto-decide
/// are routed back to the client (eventually) as a
/// [`crate::wire::request::ContributionResponse`]. Until that
/// queueing path is wired, any non-user-origin item that reaches
/// `NeedsApproval` surfaces as [`ComposeError::HookRequired`].
pub struct SessionComposer {
    client: WireContribution,
    contribution: Contribution,
    env: StoredEnv,
}

impl core::fmt::Debug for SessionComposer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionComposer")
            .field("client", &self.client)
            .field("contribution", &self.contribution)
            .field("env", &"<closure>")
            .finish()
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SessionComposer>();
};

impl SessionComposer {
    /// Construct a composer seeded with the client's wire
    /// contribution and the default env lookup
    /// ([`std::env::var`]).
    #[must_use]
    pub fn new(client: WireContribution) -> Self {
        Self {
            client,
            contribution: Contribution::new(),
            env: default_env(),
        }
    }

    /// Replace the env lookup.
    #[must_use]
    pub fn with_env(mut self, env: StoredEnv) -> Self {
        self.env = env;
        self
    }

    /// Add a daemon-side [`Composable`] (typically project- or
    /// package-level) to this composer's accumulator. The wire
    /// contribution passed at construction is kept separate and
    /// joined back in during [`Self::compose`].
    ///
    /// # Errors
    ///
    /// Returns any error the contributor surfaces from [`Composable::contribute`].
    pub fn add(&mut self, c: impl Composable) -> Result<(), Error> {
        let incoming = c.contribute(&*self.env)?;
        self.contribution = std::mem::take(&mut self.contribution).merge(incoming)?;
        Ok(())
    }

    /// Add a sequence of contributors.
    ///
    /// # Errors
    ///
    /// Returns the first error from any contributor.
    pub fn add_all<C, I>(&mut self, items: I) -> Result<(), Error>
    where
        C: Composable,
        I: IntoIterator<Item = C>,
    {
        for c in items {
            self.add(c)?;
        }
        Ok(())
    }

    /// Compose daemon-side items against `policy`, then append the
    /// client's already-gated contribution.
    ///
    /// The policy is unchanged on return — hooks (which could update
    /// it) don't run here; that happens on the client when verdicts
    /// are generated for the daemon's `ContributionResponse`.
    ///
    /// # Errors
    ///
    /// See [`ComposeError`]. In particular, [`ComposeError::HookRequired`]
    /// fires when a non-user-origin item reaches `NeedsApproval` — the
    /// daemon has no way to prompt and the multi-phase routing to the
    /// client isn't wired yet.
    pub fn compose(
        self,
        policy: UserPolicy,
        options: ComposeOptions,
    ) -> Result<Composition, ComposeError> {
        let (mut composition, _final_policy) =
            compose_contribution(self.contribution, policy, None, options, &*self.env)?;
        composition.extend_from_wire(self.client)?;
        Ok(composition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::source::{Provenanced, Source};
    use crate::wire::primitives::{WireResolvedVar, WireSessionVar, WireSource};

    fn user_loadout() -> Source {
        Source::UserLoadout { name: "dev".into() }
    }

    /// Empty wire contribution + no daemon items → empty composition.
    #[test]
    fn empty_inputs_produce_empty_composition() {
        let composer = SessionComposer::new(WireContribution::default());
        let res = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert!(res.vars().is_empty());
        assert!(res.patches().is_empty());
        assert!(res.packages().is_empty());
        assert!(res.lifecycle_hooks().is_empty());
    }

    /// Client-contributed vars survive into the merged composition.
    #[test]
    fn client_vars_appear_in_merged_composition() {
        let client = WireContribution {
            vars: vec![WireSessionVar {
                var: WireResolvedVar {
                    name: "EDITOR".into(),
                    value: "hx".into(),
                },
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            ..Default::default()
        };
        let composer = SessionComposer::new(client);
        let res = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        assert_eq!(res.vars().len(), 1);
        let merged = &res.vars()[0];
        assert_eq!(merged.var().name(), "EDITOR");
        assert_eq!(merged.var().value(), "hx");
        assert_eq!(merged.source(), &user_loadout());
    }
}
