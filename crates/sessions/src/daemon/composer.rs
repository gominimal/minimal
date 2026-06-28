//! Daemon-side composer: takes the client's wire contribution, gathers
//! project and package contributions, and produces a final
//! [`Composition`].

use crate::SessionId;
use crate::core::compose::{
    Composable, ComposeError, ComposeOptions, Composition, Contribution, Error, StoredEnv,
    contribution_to_pending, default_env,
};
use crate::core::source::{ProvenancedHook, ProvenancedPackage};
use crate::wire::request::{ContributionResponse, WireContribution};

/// Daemon-side state that survives a `Pending` outcome and feeds
/// into Phase 4 once the client's verdict comes back.
///
/// Packages and lifecycle hooks have no per-item verdict (the wire
/// schema doesn't carry verdicts for them), so the daemon retains
/// its own copy here. `client_contribution` is the client's
/// already-gated wire contribution, untouched — Phase 4 calls
/// [`Composition::extend_from_wire`] on it after the verdict
/// resolves the pending vars/patches.
///
/// [`Composition::extend_from_wire`]: crate::core::compose::Composition::extend_from_wire
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingComposeState {
    /// Daemon-collected packages. The wire response has no slot for
    /// them; the daemon installs them when Phase 4 finalizes.
    pub daemon_packages: Vec<ProvenancedPackage>,
    /// Daemon-collected lifecycle hooks. A copy goes in the wire
    /// response for client-side audit; the daemon also retains this
    /// copy for Phase 4 install.
    pub daemon_lifecycle_hooks: Vec<ProvenancedHook>,
    /// Client's already-gated wire contribution, untouched.
    pub client_contribution: WireContribution,
}

/// Output of [`SessionComposer::compose`].
///
/// `Ready` fires when the daemon collected no vars and no patches —
/// the only two domains with a per-item user-policy gate. Packages
/// and lifecycle hooks pass through on this path. Today every
/// internal caller hits the narrower case where the daemon
/// collected nothing at all. `Pending` fires when the daemon
/// collected a var or patch the client must gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeOutcome {
    /// All items decided; the assembled Composition is ready to apply.
    Ready(Composition),
    /// The client must gate `response.vars` and `response.patches`
    /// before composition completes. `state` is the daemon-side
    /// stash Phase 4 will need to finalize.
    Pending {
        /// Wire payload the daemon ships back to the client.
        response: ContributionResponse,
        /// Daemon-side state retained for Phase 4. Not on the wire.
        state: PendingComposeState,
    },
}

/// Accumulator for daemon-side contributions (project + packages),
/// joined with the client's already-gated wire contribution.
///
/// [`Self::compose`] returns [`ComposeOutcome::Ready`] when the
/// daemon collected no vars and no patches — the only two domains
/// with a per-item user-policy gate. Daemon-collected packages and
/// lifecycle hooks pass through on that path (the all-decided fast
/// path runs the cross-process merge via
/// [`Composition::extend_from_wire`] and finalizes). It returns
/// [`ComposeOutcome::Pending`] when the daemon collected a var or
/// patch that needs the client's verdict — the daemon never runs
/// user policy, so Pending items are routed back to the client
/// for Phase 3 gating.
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
        // `merge` is internally atomic — on `Err`, `self.contribution`
        // is untouched.
        self.contribution.merge(incoming)?;
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

    /// Drive Phase 2: produce either a finalized [`Composition`] or a
    /// [`ContributionResponse`] for the client to gate.
    ///
    /// **The daemon never runs user policy.** This method routes any
    /// daemon-collected var or patch back to the client as a pending
    /// item — the client applies its `policy` and `PolicyHooks` in
    /// Phase 3, and a future `SubmitVerdict` handler resumes from
    /// the returned [`PendingComposeState`].
    ///
    /// The branching is on `vars + patches` — those are the only
    /// items with a per-item policy gate. A daemon contribution
    /// that only carries packages and/or lifecycle hooks takes the
    /// all-decided path: packages and hooks have no verdict slot in
    /// the wire schema, the daemon installs them as declared. On
    /// that path the daemon-collected packages and hooks land in
    /// the assembled `Composition` and are merged with the client's
    /// already-gated wire contribution via
    /// [`Composition::extend_from_wire`].
    ///
    /// When the daemon collected nothing (today's only path — every
    /// internal caller sends `WireContribution::default()`), the
    /// fast-path body collapses to a single `extend_from_wire` call
    /// against an empty `Composition`.
    ///
    /// **Compared to the pre-Phase-2 single-shot path**, the new
    /// signature drops the `UserPolicy` parameter the old `compose`
    /// took — the daemon never runs user policy, so threading it
    /// here was always misleading. For the empty-contribution case
    /// (which is what every existing caller exercises today), the
    /// observable behavior is byte-equivalent.
    ///
    /// `session_id` is the daemon-allocated id; it goes on the
    /// `Pending` response so the client can correlate a future
    /// `SubmitVerdict`. It's accepted as a parameter rather than
    /// generated here because the manager allocates ids at
    /// `Loader::create` time.
    ///
    /// `_options` is reserved for the future composition pipeline
    /// (e.g. symlink-following on patch walks). Today's daemon-side
    /// path doesn't run the gate, so the parameter is ignored;
    /// kept on the signature so the call site is forward-compatible.
    ///
    /// # Errors
    ///
    /// See [`ComposeError`]. The daemon path produces
    /// [`ComposeError::InvalidWireItem`] (from wire→domain
    /// conversion in `extend_from_wire`) or [`ComposeError::Conflict`]
    /// (cross-process disagreement) on the all-decided branch.
    pub fn compose(
        self,
        session_id: SessionId,
        _options: ComposeOptions,
    ) -> Result<ComposeOutcome, ComposeError> {
        let Self {
            client,
            contribution,
            env: _,
        } = self;
        let Contribution {
            vars,
            patches,
            packages,
            lifecycle_hooks,
        } = contribution;

        // All-decided fast path: only items the client must gate are
        // vars and patches. Packages and lifecycle hooks have no
        // per-item verdict in the wire schema, so a daemon
        // contribution carrying only those (or carrying nothing)
        // assembles directly into the Composition.
        if vars.is_empty() && patches.is_empty() {
            let mut composition = Composition::from_daemon_passthrough(packages, lifecycle_hooks);
            composition.extend_from_wire(client)?;
            return Ok(ComposeOutcome::Ready(composition));
        }

        // Daemon-collected vars or patches: route them back to the
        // client for gating. Lifecycle hooks ride in the response
        // for audit; a separate copy is retained on the stash for
        // Phase 4 to install. Packages aren't on the wire at all —
        // they only live on the stash.
        let pending = contribution_to_pending(vars, patches, lifecycle_hooks.clone());
        let response = ContributionResponse {
            session_id,
            vars: pending.vars,
            patches: pending.patches,
            lifecycle_hooks: pending.lifecycle_hooks,
        };
        Ok(ComposeOutcome::Pending {
            response,
            state: PendingComposeState {
                daemon_packages: packages,
                daemon_lifecycle_hooks: lifecycle_hooks,
                client_contribution: client,
            },
        })
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

    fn nil_id() -> SessionId {
        SessionId::nil()
    }

    fn unwrap_ready(outcome: ComposeOutcome) -> Composition {
        match outcome {
            ComposeOutcome::Ready(c) => c,
            ComposeOutcome::Pending { .. } => panic!("expected Ready, got Pending"),
        }
    }

    /// Empty wire contribution + no daemon items → empty composition
    /// via the all-decided fast path.
    #[test]
    fn empty_inputs_produce_empty_composition() {
        let composer = SessionComposer::new(WireContribution::default());
        let res = unwrap_ready(
            composer
                .compose(nil_id(), ComposeOptions::default())
                .unwrap(),
        );
        assert!(res.vars().is_empty());
        assert!(res.patches().is_empty());
        assert!(res.packages().is_empty());
        assert!(res.lifecycle_hooks().is_empty());
    }

    /// A daemon-collected var becomes a `Pending` outcome with the
    /// item in `response.vars` and the original session id on the
    /// response. No policy is applied on the daemon side — the var
    /// is routed back for the client to gate.
    #[test]
    fn daemon_collected_var_routes_to_pending() {
        use crate::core::compose::{Composable, Contribution, Error};
        use crate::core::primitives::{LenientVarEntry, LenientVarName, ResolvedVar, VarValue};
        use crate::core::source::ProvenancedVar;
        use crate::wire::primitives::WireVarSpec;

        /// Test-only composable that emits a single project-origin var.
        struct ProjectVar;
        impl Composable for ProjectVar {
            fn contribute(
                self,
                _env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
            ) -> Result<Contribution, Error> {
                let entry = LenientVarEntry::new(
                    LenientVarName::try_new("PROJECT_VAR")?,
                    VarValue::specified("from-project"),
                );
                let (name, value) = entry.into_parts();
                let resolved = ResolvedVar::resolve_with(name.into_inner(), value, |_| {
                    Err(std::env::VarError::NotPresent)
                })?;
                let mut c = Contribution::new();
                c.push_var(ProvenancedVar::new(
                    resolved,
                    Source::Project {
                        path: paths::HostPath::new("/proj"),
                    },
                ));
                Ok(c)
            }
        }

        let mut composer = SessionComposer::new(WireContribution::default());
        composer.add(ProjectVar).unwrap();

        let id = SessionId::parse_str("00000000-0000-0000-0000-000000000007").unwrap();
        let outcome = composer.compose(id, ComposeOptions::default()).unwrap();
        match outcome {
            ComposeOutcome::Pending { response, state } => {
                assert_eq!(response.session_id, id);
                assert_eq!(response.vars.len(), 1);
                let v = &response.vars[0];
                assert_eq!(v.name, "PROJECT_VAR");
                // Already-resolved → ships as Specified so the client
                // doesn't re-resolve against its env.
                assert!(
                    matches!(&v.spec, WireVarSpec::Specified { value } if value == "from-project")
                );
                assert!(response.patches.is_empty());
                assert!(response.lifecycle_hooks.is_empty());
                // Stash is empty (no packages or hooks collected); the
                // client's wire contribution is the default we passed.
                assert!(state.daemon_packages.is_empty());
                assert!(state.daemon_lifecycle_hooks.is_empty());
                assert_eq!(state.client_contribution, WireContribution::default());
            }
            ComposeOutcome::Ready(_) => panic!("expected Pending, got Ready"),
        }
    }

    /// A daemon contribution carrying packages and lifecycle hooks
    /// (but no vars or patches) takes the all-decided fast path —
    /// neither domain has a per-item verdict slot, so they pass
    /// through verbatim into the assembled [`Composition`].
    /// Regression guard for branching on `vars + patches` (not
    /// `Contribution::is_empty()`).
    #[test]
    fn daemon_collected_packages_and_hooks_route_to_ready() {
        use crate::core::compose::{Composable, Contribution, Error};
        use crate::core::lifecyclehook::{HookScript, LifecycleHook};
        use crate::core::source::ProvenancedHook;

        /// Test-only composable that emits one package and one hook,
        /// both with project provenance, and no vars or patches.
        struct ProjectPkgAndHook;
        impl Composable for ProjectPkgAndHook {
            fn contribute(
                self,
                _env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
            ) -> Result<Contribution, Error> {
                let src = Source::Project {
                    path: paths::HostPath::new("/proj"),
                };
                let hook = LifecycleHook::builder()
                    .with_on_activate(HookScript::inline("echo go"))
                    .build()
                    .expect("hook has at least one callback");
                let mut c = Contribution::new();
                c.push_package(ProvenancedPackage::new("ripgrep", src.clone()));
                c.push_hook(ProvenancedHook::new(hook, src));
                Ok(c)
            }
        }

        let mut composer = SessionComposer::new(WireContribution::default());
        composer.add(ProjectPkgAndHook).unwrap();

        let res = unwrap_ready(
            composer
                .compose(nil_id(), ComposeOptions::default())
                .unwrap(),
        );
        // Vars and patches are untouched; pkg and hook passed
        // through onto the Composition.
        assert!(res.vars().is_empty());
        assert!(res.patches().is_empty());
        assert_eq!(res.packages().len(), 1);
        assert_eq!(res.packages()[0].package(), "ripgrep");
        assert_eq!(res.lifecycle_hooks().len(), 1);
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
        let res = unwrap_ready(
            composer
                .compose(nil_id(), ComposeOptions::default())
                .unwrap(),
        );
        assert_eq!(res.vars().len(), 1);
        let merged = &res.vars()[0];
        assert_eq!(merged.var().name(), "EDITOR");
        assert_eq!(merged.var().value(), "hx");
        assert_eq!(merged.source(), &user_loadout());
    }
}
