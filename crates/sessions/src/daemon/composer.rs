//! Daemon-side composer: takes the client's wire contribution, gathers
//! project and package contributions, and produces a final
//! [`Composition`].

use std::collections::BTreeMap;

use crate::SessionId;
use crate::core::compose::{
    Composable, ComposeError, ComposeOptions, Composition, Contribution, Error, SessionPatch,
    SessionVar, StoredEnv, contribution_to_pending, deferring_env,
};
use crate::core::primitives::ResolvedPatch;
use crate::core::source::{
    Provenanced, ProvenancedHook, ProvenancedPackage, ProvenancedPatch, ProvenancedVar, Source,
};
use crate::wire::policy::{WirePatchVerdict, WireVarVerdict};
use crate::wire::primitives::PendingId;
use crate::wire::request::{ContributionResponse, ContributionVerdict, WireContribution};

/// Daemon-side state retained across a `Pending` outcome. Fed back
/// into [`resume_from_verdict`] once the client's verdict returns
/// to reattach provenance the wire schema doesn't carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingComposeState {
    /// Daemon-collected packages (no per-item wire verdict).
    pub daemon_packages: Vec<ProvenancedPackage>,
    /// Daemon-collected lifecycle hooks (no per-item wire verdict).
    pub daemon_lifecycle_hooks: Vec<ProvenancedHook>,
    /// Daemon-collected vars keyed by the [`PendingId`] shipped on
    /// the wire response. Supplies source provenance the verdict
    /// omits.
    pub pending_vars: BTreeMap<PendingId, ProvenancedVar>,
    /// Daemon-collected patches keyed by [`PendingId`]. Supplies
    /// destination and source provenance the verdict omits.
    pub pending_patches: BTreeMap<PendingId, ProvenancedPatch>,
    /// Client's already-gated wire contribution, untouched.
    pub client_contribution: WireContribution,
}

/// Output of [`SessionComposer::compose`]. `Ready` when the daemon
/// collected no items needing a per-item user gate (vars, patches);
/// `Pending` when the client must supply a verdict before the
/// composition can finalize via [`resume_from_verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeOutcome {
    /// All items decided; the assembled composition is ready.
    Ready(Composition),
    /// The client must gate `response.vars` and `response.patches`
    /// before composition completes; hand `state` back to
    /// [`resume_from_verdict`] once the verdict returns.
    Pending {
        response: ContributionResponse,
        state: PendingComposeState,
    },
}

/// Accumulator for daemon-side contributions (project + packages),
/// joined with the client's already-gated wire contribution to
/// produce a [`ComposeOutcome`].
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
    /// contribution and the daemon-side [`deferring_env`] lookup —
    /// inherited vars are never resolved against the daemon's own
    /// environment; the client resolves them against the user's env.
    #[must_use]
    pub fn new(client: WireContribution) -> Self {
        Self {
            client,
            contribution: Contribution::new(),
            env: deferring_env(),
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

    /// Produce a finalized [`Composition`], or a
    /// [`ContributionResponse`] the client must gate before
    /// resuming via `SubmitVerdict`.
    ///
    /// The daemon never runs user policy. Any daemon-collected var
    /// or patch is routed back to the client as a pending item; a
    /// daemon contribution carrying only packages and/or lifecycle
    /// hooks (which have no per-item gate) is installed as-is and
    /// merged with the client's already-gated wire contribution.
    ///
    /// `session_id` correlates a future `SubmitVerdict` back to
    /// this compose call.
    ///
    /// # Errors
    ///
    /// See [`ComposeError`].
    pub fn compose(
        self,
        session_id: SessionId,
        _options: ComposeOptions,
    ) -> Result<ComposeOutcome, ComposeError> {
        let Self {
            client,
            mut contribution,
            env: _,
        } = self;
        // Packages may not supply patches, nor vars that carry user data
        // (env-inherited values). Strip them before gating so they never
        // reach the client as pending items or land in the Composition;
        // an item a package shares with a project or loadout still
        // composes in via that other source's own entry.
        contribution.drop_package_supplied_patches_and_user_data_vars();
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
        tracing::info!(
            daemon_vars = vars.len(),
            daemon_patches = patches.len(),
            daemon_packages = packages.len(),
            "compose: daemon-side contribution collected",
        );
        if vars.is_empty() && patches.is_empty() {
            let mut composition = Composition::from_daemon_passthrough(packages, lifecycle_hooks);
            composition.extend_from_wire(client)?;
            return Ok(ComposeOutcome::Ready(composition));
        }

        // Daemon-collected vars or patches: route them back to the
        // client for gating. Lifecycle hooks ride in the response
        // for audit; a separate copy is retained on the stash for
        // Phase 4 to install. Packages aren't on the wire at all —
        // they only live on the stash. Vars and patches are stashed
        // by `PendingId` so `resume_from_verdict` can reattach
        // provenance to whatever the client approves.
        let transform = contribution_to_pending(vars, patches, lifecycle_hooks.clone());
        let response = ContributionResponse {
            session_id,
            vars: transform.wire.vars,
            patches: transform.wire.patches,
            lifecycle_hooks: transform.wire.lifecycle_hooks,
        };
        Ok(ComposeOutcome::Pending {
            response,
            state: PendingComposeState {
                daemon_packages: packages,
                daemon_lifecycle_hooks: lifecycle_hooks,
                pending_vars: transform.pending_vars,
                pending_patches: transform.pending_patches,
                client_contribution: client,
            },
        })
    }
}

/// Assemble a finalized [`Composition`] from the daemon's stashed
/// [`PendingComposeState`] and the client's [`ContributionVerdict`].
/// Pure: no env, no policy — every value and decision arrives on
/// the verdict.
///
/// `Approved` items are included; `Ignored` items are dropped; a
/// single `Denied` aborts the whole resume with
/// [`ComposeError::Denied`], because a project- or package-declared
/// item the user explicitly rejected can't be silently dropped —
/// the resulting session would be inconsistent with what its
/// sources declared.
///
/// # Errors
///
/// - [`ComposeError::InvalidWireItem`] if the verdict references a
///   [`PendingId`] absent from the stash, or omits one that was
///   pending.
/// - [`ComposeError::Denied`] if any entry is `Denied`.
/// - [`ComposeError::Conflict`] / [`ComposeError::InvalidWireItem`]
///   from merging the client's wire contribution.
pub fn resume_from_verdict(
    state: PendingComposeState,
    verdict: ContributionVerdict,
) -> Result<Composition, ComposeError> {
    let PendingComposeState {
        daemon_packages,
        daemon_lifecycle_hooks,
        pending_vars,
        pending_patches,
        client_contribution,
    } = state;

    let mut composition =
        Composition::from_daemon_passthrough(daemon_packages, daemon_lifecycle_hooks);

    let accepted_vars = apply_var_verdicts(pending_vars, verdict.vars)?;
    let accepted_patches = apply_patch_verdicts(&pending_patches, verdict.patches)?;
    composition.extend_with(accepted_vars, accepted_patches)?;
    composition.extend_from_wire(client_contribution)?;
    Ok(composition)
}

/// Walk the var verdict, draining `pending_vars` as items are
/// addressed. Returns the [`SessionVar`]s that survived (Approved
/// items reattached to their stashed source) or surfaces a structured
/// error for: missing/unknown `PendingId`s, omitted stash entries,
/// or a `Denied` verdict (which terminates the resume).
fn apply_var_verdicts(
    mut pending_vars: BTreeMap<PendingId, ProvenancedVar>,
    var_verdicts: Vec<WireVarVerdict>,
) -> Result<Vec<SessionVar>, ComposeError> {
    // Snapshot every stashed var's source before walking the
    // verdict. The walk drains `pending_vars` via `take_pending`,
    // so a duplicate-id verdict (Approved then Denied for the same
    // id, or two Denieds for the same id) would otherwise see an
    // already-drained stash and need to fall back to a placeholder
    // for the `Denied` provenance. The snapshot makes the lookup
    // order-independent and lets a duplicate id surface as a
    // structured `InvalidWireItem` instead.
    let pending_var_sources: BTreeMap<PendingId, Source> = pending_vars
        .iter()
        .map(|(id, pv)| (*id, pv.source().clone()))
        .collect();

    let mut accepted: Vec<SessionVar> = Vec::new();
    // A `PendingId` fans out to at most one var verdict — unlike
    // patches, where one pending fans out to many files, each id
    // here maps 1:1 to a pending var. A verdict carrying two entries
    // for the same id (Approved+Approved, Approved+Ignored, etc.) is
    // a broken client. Detect it with a `seen` set so the second
    // occurrence surfaces as an actionable `duplicate` error rather
    // than as the `unknown` fallout of the first occurrence having
    // already drained the stash. Mirrors `apply_patch_verdicts`.
    let mut seen: std::collections::BTreeSet<PendingId> = std::collections::BTreeSet::new();
    for v in var_verdicts {
        let id_for_dedupe = match &v {
            WireVarVerdict::Approved { id, .. }
            | WireVarVerdict::Ignored { id, .. }
            | WireVarVerdict::Denied { id, .. } => *id,
        };
        if !seen.insert(id_for_dedupe) {
            return Err(ComposeError::InvalidWireItem {
                what: "verdict contains duplicate var entry",
                context: format!("pending id {id_for_dedupe:?}"),
            });
        }
        match v {
            WireVarVerdict::Approved { id, value } => {
                let pv = take_pending(&mut pending_vars, id, "var")?;
                // The verdict's `value` is the client-resolved
                // (possibly user-edited at prompt) value; the
                // stashed `pv` supplies the source the wire schema
                // doesn't echo.
                let (_, source) = pv.into_parts();
                accepted.push(SessionVar::new(value.into(), source));
            }
            WireVarVerdict::Ignored { id, name: _ } => {
                take_pending(&mut pending_vars, id, "var")?;
            }
            WireVarVerdict::Denied { id, name } => {
                let from =
                    pending_var_sources
                        .get(&id)
                        .cloned()
                        .ok_or(ComposeError::InvalidWireItem {
                            what: "verdict references unknown pending var id",
                            context: format!("denied var id {id:?} (`{name}`)"),
                        })?;
                return Err(ComposeError::Denied { what: name, from });
            }
        }
    }
    if let Some((id, pv)) = pending_vars.into_iter().next() {
        return Err(ComposeError::InvalidWireItem {
            what: "verdict missing entry for pending var",
            context: format!("pending id {id:?} (`{}`)", pv.var().name()),
        });
    }
    Ok(accepted)
}

/// Walk the patch verdict against the stash without consuming
/// entries — a single stashed `PendingId` backs many verdicts (one
/// per glob match). Returns the [`SessionPatch`]es that survived or
/// surfaces a structured error for: duplicate `(id, host_path)`
/// entries, missing/unknown `PendingId`s, stash entries the verdict
/// never mentioned, or a `Denied` verdict.
fn apply_patch_verdicts(
    pending_patches: &BTreeMap<PendingId, ProvenancedPatch>,
    patch_verdicts: Vec<WirePatchVerdict>,
) -> Result<Vec<SessionPatch>, ComposeError> {
    let mut accepted: Vec<SessionPatch> = Vec::new();
    let mut touched_ids: std::collections::BTreeSet<PendingId> = std::collections::BTreeSet::new();
    // Verdicts are deduped by `(PendingId, host_path)` — a client
    // bug that submits two decisions for the same matched file
    // (e.g. Approved then Ignored) would otherwise silently land
    // one of them in the composition; instead, the duplicate
    // surfaces as a structured error.
    let mut seen_entries: std::collections::BTreeSet<(PendingId, paths::HostAbsPath)> =
        std::collections::BTreeSet::new();
    for p in patch_verdicts {
        let (id, host_path_for_dedupe) = match &p {
            WirePatchVerdict::Approved { id, host_path, .. }
            | WirePatchVerdict::Ignored { id, host_path }
            | WirePatchVerdict::Denied { id, host_path } => (*id, host_path.clone()),
        };
        if !seen_entries.insert((id, host_path_for_dedupe.clone())) {
            return Err(ComposeError::InvalidWireItem {
                what: "verdict contains duplicate patch entry",
                context: format!(
                    "pending id {id:?}, host_path `{}`",
                    host_path_for_dedupe.as_str(),
                ),
            });
        }

        match p {
            WirePatchVerdict::Approved {
                id,
                host_path,
                destination,
            } => {
                let pp = lookup_patch(pending_patches, id)?;
                touched_ids.insert(id);
                // Use the client-computed `destination`, not
                // `pp.patch().dest()`. The pending's dest is the
                // base (e.g. `~/.claude` for a `~/.claude/**` dir
                // mapping) — reusing it would collapse every file's
                // dest to that base and trigger the composer's
                // patch-destination-conflict check on the second
                // file. See the wire-side rationale on
                // `WirePatchVerdict::Approved::destination`.
                //
                // Safe against sandbox-escape via a `..` traversal:
                // `destination` deserialized through
                // `SandboxRelPath::try_new`, which rejects both
                // absolute paths and any `..` component. A malicious
                // client crafting `"../../etc/foo"` never gets past
                // wire parsing.
                let source = pp.source().clone();
                accepted.push(SessionPatch::new(
                    ResolvedPatch::new(host_path, destination),
                    source,
                ));
            }
            WirePatchVerdict::Ignored { id, host_path: _ } => {
                lookup_patch(pending_patches, id)?;
                touched_ids.insert(id);
            }
            WirePatchVerdict::Denied { id, host_path } => {
                let pp = lookup_patch(pending_patches, id)?;
                let from = pp.source().clone();
                return Err(ComposeError::Denied {
                    what: host_path.as_str().to_string(),
                    from,
                });
            }
        }
    }
    // Every stashed pending patch must have been mentioned at least
    // once by the verdict — a glob that matched zero files on the
    // client should still emit an `Ignored` entry per file, or, if
    // truly zero, a synthetic `Ignored { id, host_path: <glob> }`.
    // The client today does this; missing means a malformed verdict.
    if let Some((id, pp)) = pending_patches
        .iter()
        .find(|(id, _)| !touched_ids.contains(id))
    {
        return Err(ComposeError::InvalidWireItem {
            what: "verdict missing entry for pending patch",
            context: format!(
                "pending id {id:?} (source pattern `{}`)",
                pp.patch().source(),
            ),
        });
    }
    Ok(accepted)
}

/// Pop a stashed pending item by id, returning a structured error if
/// the verdict referenced an id that isn't on the stash. Shared by
/// the var branches of [`resume_from_verdict`].
fn take_pending<T>(
    map: &mut BTreeMap<PendingId, T>,
    id: PendingId,
    domain: &'static str,
) -> Result<T, ComposeError> {
    map.remove(&id).ok_or(ComposeError::InvalidWireItem {
        what: "verdict references unknown pending id",
        context: format!("{domain} id {id:?}"),
    })
}

/// Look up a stashed pending patch by id without consuming the entry —
/// a single stashed [`ProvenancedPatch`] backs many wire verdicts (one
/// per expanded glob match), so the stash entry must outlive any single
/// lookup. Returns a structured error if the id isn't on the stash.
fn lookup_patch(
    map: &BTreeMap<PendingId, ProvenancedPatch>,
    id: PendingId,
) -> Result<&ProvenancedPatch, ComposeError> {
    map.get(&id).ok_or(ComposeError::InvalidWireItem {
        what: "verdict references unknown pending patch id",
        context: format!("pending id {id:?}"),
    })
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

    // ============================================================
    // resume_from_verdict
    // ============================================================

    /// Build a `PendingComposeState` with a single daemon-collected
    /// `PROJECT_VAR` keyed at `PendingId(0)`. Mirrors what
    /// `SessionComposer::compose` would have stashed.
    fn stash_with_one_var(value: &str) -> (PendingComposeState, SessionId) {
        use crate::core::primitives::{ResolvedVar, VarValue};
        let id = SessionId::parse_str("00000000-0000-0000-0000-000000000042").unwrap();
        let resolved =
            ResolvedVar::resolve_with("PROJECT_VAR".into(), VarValue::specified(value), |_| {
                Err(std::env::VarError::NotPresent)
            })
            .unwrap();
        let pv = ProvenancedVar::new(
            resolved,
            Source::Project {
                path: paths::HostPath::new("/proj"),
            },
        );
        let mut pending_vars = BTreeMap::new();
        pending_vars.insert(PendingId::new(0), pv);
        let state = PendingComposeState {
            daemon_packages: Vec::new(),
            daemon_lifecycle_hooks: Vec::new(),
            pending_vars,
            pending_patches: BTreeMap::new(),
            client_contribution: WireContribution::default(),
        };
        (state, id)
    }

    /// An `Approved` verdict lands the var on the `Composition` with
    /// the verdict's value and the stashed source — provenance is
    /// reattached.
    #[test]
    fn resume_from_verdict_keeps_approved_var() {
        let (state, id) = stash_with_one_var("from-project");
        let verdict = ContributionVerdict {
            session_id: id,
            vars: vec![WireVarVerdict::Approved {
                id: PendingId::new(0),
                value: WireResolvedVar {
                    name: "PROJECT_VAR".into(),
                    value: "approved-value".into(),
                    carries_user_data: true,
                },
            }],
            patches: vec![],
        };
        let comp = resume_from_verdict(state, verdict).unwrap();
        assert_eq!(comp.vars().len(), 1);
        assert_eq!(comp.vars()[0].var().name(), "PROJECT_VAR");
        assert_eq!(comp.vars()[0].var().value(), "approved-value");
        assert!(matches!(comp.vars()[0].source(), Source::Project { .. },));
    }

    /// An `Ignored` verdict drops the item silently.
    #[test]
    fn resume_from_verdict_drops_ignored_var() {
        let (state, id) = stash_with_one_var("v");
        let verdict = ContributionVerdict {
            session_id: id,
            vars: vec![WireVarVerdict::Ignored {
                id: PendingId::new(0),
                name: "PROJECT_VAR".into(),
            }],
            patches: vec![],
        };
        let comp = resume_from_verdict(state, verdict).unwrap();
        assert!(comp.vars().is_empty());
    }

    /// A `Denied` verdict aborts with `ComposeError::Denied`.
    #[test]
    fn resume_from_verdict_denied_var_aborts() {
        let (state, id) = stash_with_one_var("v");
        let verdict = ContributionVerdict {
            session_id: id,
            vars: vec![WireVarVerdict::Denied {
                id: PendingId::new(0),
                name: "PROJECT_VAR".into(),
            }],
            patches: vec![],
        };
        let err = resume_from_verdict(state, verdict).unwrap_err();
        match err {
            ComposeError::Denied { what, from } => {
                assert_eq!(what, "PROJECT_VAR");
                assert!(matches!(from, Source::Project { .. }));
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// A verdict referencing a `PendingId` the stash doesn't have →
    /// `InvalidWireItem`. Catches mis-correlated verdicts.
    #[test]
    fn resume_from_verdict_unknown_pending_id_errors() {
        let (state, id) = stash_with_one_var("v");
        let verdict = ContributionVerdict {
            session_id: id,
            vars: vec![WireVarVerdict::Approved {
                id: PendingId::new(99),
                value: WireResolvedVar {
                    name: "PROJECT_VAR".into(),
                    value: "v".into(),
                    carries_user_data: true,
                },
            }],
            patches: vec![],
        };
        let err = resume_from_verdict(state, verdict).unwrap_err();
        assert!(
            matches!(err, ComposeError::InvalidWireItem { what, .. } if what.contains("unknown")),
            "expected InvalidWireItem(unknown), got {err:?}",
        );
    }

    /// A verdict that omits an entry the stash holds → `InvalidWireItem`.
    /// Catches under-specified verdicts that would leave items
    /// silently in limbo.
    #[test]
    fn resume_from_verdict_missing_entry_errors() {
        let (state, id) = stash_with_one_var("v");
        let verdict = ContributionVerdict {
            session_id: id,
            vars: vec![],
            patches: vec![],
        };
        let err = resume_from_verdict(state, verdict).unwrap_err();
        assert!(
            matches!(err, ComposeError::InvalidWireItem { what, .. } if what.contains("missing")),
            "expected InvalidWireItem(missing), got {err:?}",
        );
    }

    /// A stash with zero pending items + an empty verdict still
    /// works — the path is degenerate (the composer wouldn't have
    /// produced a Pending outcome from no pending items) but the
    /// fn shouldn't error.
    #[test]
    fn resume_from_verdict_empty_inputs_yields_empty_composition() {
        let state = PendingComposeState {
            daemon_packages: Vec::new(),
            daemon_lifecycle_hooks: Vec::new(),
            pending_vars: BTreeMap::new(),
            pending_patches: BTreeMap::new(),
            client_contribution: WireContribution::default(),
        };
        let verdict = ContributionVerdict {
            session_id: SessionId::nil(),
            vars: vec![],
            patches: vec![],
        };
        let comp = resume_from_verdict(state, verdict).unwrap();
        assert!(comp.vars().is_empty());
        assert!(comp.patches().is_empty());
        assert!(comp.packages().is_empty());
        assert!(comp.lifecycle_hooks().is_empty());
    }

    /// Daemon-stashed packages and lifecycle hooks pass through the
    /// resume into the assembled `Composition` (they have no
    /// per-item verdict and are never on the wire round-trip).
    #[test]
    fn resume_from_verdict_passes_through_packages_and_hooks() {
        use crate::core::lifecyclehook::{HookScript, LifecycleHook};
        let src = Source::Project {
            path: paths::HostPath::new("/proj"),
        };
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::inline("echo hi"))
            .build()
            .unwrap();
        let state = PendingComposeState {
            daemon_packages: vec![ProvenancedPackage::new("ripgrep", src.clone())],
            daemon_lifecycle_hooks: vec![ProvenancedHook::new(hook, src)],
            pending_vars: BTreeMap::new(),
            pending_patches: BTreeMap::new(),
            client_contribution: WireContribution::default(),
        };
        let verdict = ContributionVerdict {
            session_id: SessionId::nil(),
            vars: vec![],
            patches: vec![],
        };
        let comp = resume_from_verdict(state, verdict).unwrap();
        assert_eq!(comp.packages().len(), 1);
        assert_eq!(comp.packages()[0].package(), "ripgrep");
        assert_eq!(comp.lifecycle_hooks().len(), 1);
    }

    /// The client's stashed wire contribution merges in on top of
    /// the verdict-derived vars/patches.
    #[test]
    fn resume_from_verdict_merges_client_wire_contribution() {
        let client = WireContribution {
            vars: vec![WireSessionVar {
                var: WireResolvedVar {
                    name: "EDITOR".into(),
                    value: "hx".into(),
                    carries_user_data: true,
                },
                source: WireSource::UserLoadout { name: "dev".into() },
            }],
            ..Default::default()
        };
        let state = PendingComposeState {
            daemon_packages: Vec::new(),
            daemon_lifecycle_hooks: Vec::new(),
            pending_vars: BTreeMap::new(),
            pending_patches: BTreeMap::new(),
            client_contribution: client,
        };
        let verdict = ContributionVerdict {
            session_id: SessionId::nil(),
            vars: vec![],
            patches: vec![],
        };
        let comp = resume_from_verdict(state, verdict).unwrap();
        assert_eq!(comp.vars().len(), 1);
        assert_eq!(comp.vars()[0].var().name(), "EDITOR");
    }

    /// Client-contributed vars survive into the merged composition.
    #[test]
    fn client_vars_appear_in_merged_composition() {
        let client = WireContribution {
            vars: vec![WireSessionVar {
                var: WireResolvedVar {
                    name: "EDITOR".into(),
                    value: "hx".into(),
                    carries_user_data: true,
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
