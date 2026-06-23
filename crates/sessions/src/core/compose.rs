//! Shared composition primitives.
//!
//! A composer accumulates [`Contribution`]s, then drives the pipeline
//! that gates them against the user's [`UserPolicy`] and assembles a
//! [`Composition`].
//!
//! The two workflows live in [`crate::client::composer::UserComposer`]
//! (user loadouts only) and [`crate::daemon::composer::SessionComposer`]
//! (project + package contributions, joined with the already-gated
//! wire contribution from the client). Both share the `pub(crate)`
//! gate functions in this module.

use core::fmt;

use crate::core::decision::{CheckOutcome, Decision, ItemDecision};
use crate::core::enumerate::{ExpandedProvenancedPatch, PatchFile, enumerate_patch_files};
use crate::core::hooks::{HookResult, PolicyHooks, Unapproved};
use crate::core::policy::{PatchPolicy, UserPolicy, VarsPolicy};
use crate::core::primitives::{ResolvedPatch, ResolvedVar, VarError};
use crate::core::source::{
    Provenanced, ProvenancedHook, ProvenancedPackage, ProvenancedPatch, ProvenancedVar, Source,
};
use crate::wire::policy::{WirePatchVerdict, WireVarVerdict};
use crate::wire::primitives::{
    PendingId, WirePendingVar, WireResolvedVar, WireSessionPatch, WireSessionVar,
};

/// Errors produced while a [`Composable`] materializes its
/// [`Contribution`], or while two contributions are merged.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A variable declaration failed validation or value resolution.
    #[error("variable contribution failed: {source}")]
    Var {
        #[from]
        source: crate::core::primitives::VarError,
    },
    /// A patch declaration failed validation.
    #[error("patch contribution failed: {source}")]
    Patch {
        #[from]
        source: crate::core::primitives::PatchError,
    },
    /// A lifecycle hook declaration failed validation.
    #[error("lifecycle hook contribution failed: {source}")]
    LifecycleHook {
        #[from]
        source: crate::core::lifecyclehook::Error,
    },
    /// Two contributions had a conflict that
    /// [`Contribution::merge`] couldn't resolve.
    #[error("contribution merge conflict: {source}")]
    Conflict {
        #[from]
        source: Conflict,
    },
}

/// Conflicts surfaced by [`Contribution::merge`].
///
/// Empty today (the merge logic just appends), reserved for the
/// upcoming conflict-detection rules (e.g. two contributors setting
/// the same variable to different values).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Conflict {}

/// A single source's contribution to a session, materialized as a
/// concrete value rather than streamed into a composer.
///
/// Returned by [`Composable::contribute`]. A composer accumulates
/// these into one bucket via [`Self::merge`] before the gate runs.
#[derive(Clone, Debug, Default)]
pub struct Contribution {
    pub(crate) vars: Vec<ProvenancedVar>,
    pub(crate) patches: Vec<ProvenancedPatch>,
    pub(crate) packages: Vec<ProvenancedPackage>,
    pub(crate) lifecycle_hooks: Vec<ProvenancedHook>,
}

impl Contribution {
    /// Construct an empty contribution.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a var in place. Useful inside a loop.
    pub fn push_var(&mut self, v: ProvenancedVar) {
        self.vars.push(v);
    }

    /// Append a patch in place.
    pub fn push_patch(&mut self, p: ProvenancedPatch) {
        self.patches.push(p);
    }

    /// Append a package in place.
    pub fn push_package(&mut self, p: ProvenancedPackage) {
        self.packages.push(p);
    }

    /// Append a lifecycle hook in place.
    pub fn push_hook(&mut self, h: ProvenancedHook) {
        self.lifecycle_hooks.push(h);
    }

    /// Merge two contributions into one. Used by composers to
    /// accumulate per-source contributions into one bucket.
    ///
    /// # Errors
    ///
    /// Returns [`Conflict`] when the upcoming merge rules detect that
    /// the two contributions disagree on an item (e.g. the same
    /// variable set to different values). Today the merge is pure
    /// concatenation, so the result is always `Ok` — the `Result`
    /// shape is reserved for those rules.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Conflict variants will land; the Result shape is the API contract"
    )]
    pub(crate) fn merge(mut self, other: Contribution) -> Result<Self, Conflict> {
        self.vars.extend(other.vars);
        self.patches.extend(other.patches);
        self.packages.extend(other.packages);
        self.lifecycle_hooks.extend(other.lifecycle_hooks);
        Ok(self)
    }

    /// All vars contributed so far.
    #[must_use]
    pub fn vars(&self) -> &[ProvenancedVar] {
        &self.vars
    }

    /// All patches contributed so far.
    #[must_use]
    pub fn patches(&self) -> &[ProvenancedPatch] {
        &self.patches
    }

    /// All packages contributed so far.
    #[must_use]
    pub fn packages(&self) -> &[ProvenancedPackage] {
        &self.packages
    }

    /// All lifecycle hooks contributed so far.
    #[must_use]
    pub fn lifecycle_hooks(&self) -> &[ProvenancedHook] {
        &self.lifecycle_hooks
    }
}

/// Boxed env-lookup closure stored on a composer.
///
/// `Send + Sync` so composers can be built on one thread and resolved
/// on another (e.g. an async server handing the composer off to a
/// worker pool). The default (a thin wrapper over [`std::env::var`])
/// trivially satisfies the bound.
pub type StoredEnv = Box<dyn Fn(&str) -> Result<String, std::env::VarError> + Send + Sync>;

/// Default env lookup used when callers don't override.
#[must_use]
pub fn default_env() -> StoredEnv {
    Box::new(|name| std::env::var(name))
}

/// Anything that can contribute primitives (vars, patches, packages,
/// lifecycle hooks) to a composer during session construction.
///
/// The current implementor is [`crate::core::loadout::Loadout`]. Project-
/// and package-level contributors will land on this trait as those
/// sources are wired in.
pub trait Composable {
    /// Produce this source's [`Contribution`].
    ///
    /// Consuming `self` matches the one-shot nature of contribution:
    /// each contributor is "spent" once it hands off its primitives.
    /// `env` resolves any inherited variables the contributor needs
    /// to materialize — production callers pass [`std::env::var`];
    /// tests pass a synthetic closure.
    ///
    /// # Errors
    ///
    /// Implementations return an [`Error`] when their primitives fail
    /// their own construction-time validation (e.g. an invalid glob,
    /// an empty patch destination, or an env lookup that surfaced an
    /// error).
    fn contribute(
        self,
        env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
    ) -> Result<Contribution, Error>;
}

// =====================================================================
// Composition: deciding what survives the user's policy
// =====================================================================

/// Errors raised by the composition pipeline.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// Policy explicitly denied an item; session construction aborts.
    ///
    /// `from` is the contributor whose item was rejected. The field is
    /// not named `source` because thiserror auto-promotes that name to
    /// [`std::error::Error::source`] and [`Source`] is provenance
    /// metadata, not an error.
    #[error("policy denied `{what}` (from {from})")]
    Denied { what: String, from: Source },
    /// User cancelled at the prompt.
    #[error("user aborted session construction")]
    Aborted,
    /// Hook returned a result that violates the contract: wrong number
    /// of decisions, or `UseRule` for an item the policy still couldn't
    /// decide after mutation. `context` names the offending item or
    /// batch so the message points somewhere concrete.
    #[error("policy hook contract violation: {kind} ({context})")]
    HookContract { kind: &'static str, context: String },
    /// An item the policy couldn't auto-decide reached a composer
    /// that doesn't carry a hook — i.e. a non-user-origin item was
    /// fed into the user-only composer. Surfaces as a programming
    /// bug in the caller, not a normal failure mode.
    #[error("non-user-origin `{what}` (from {from}) requires a policy hook, but none was provided")]
    HookRequired { what: String, from: Source },
    /// One or more patch source filesystem walks failed with IO-level
    /// errors (permission denied, non-UTF-8 paths, etc.). All errors
    /// surfaced by every `FileSet::resolve` invocation are accumulated
    /// — none are discarded.
    #[error("patch enumeration failed ({} error(s)):{}", sources.len(), DisplayJoin(sources))]
    PatchWalk {
        sources: Vec<crate::core::primitives::PatchError>,
    },
    /// A wire-form item failed conversion back to its domain type —
    /// typically a data-shape invariant the domain type enforces but
    /// the wire form can violate (e.g. a `WireLifecycleHook` with all
    /// three callback slots empty).
    #[error("invalid wire item: {what} ({context})")]
    InvalidWireItem {
        /// Short categorical label naming the offending shape.
        what: &'static str,
        /// Free-form context.
        context: String,
    },
    /// A pending patch's destination violates [`PatchDest`]'s
    /// invariants (empty path, traversal component, absolute path).
    /// Surfaces from `handle_response` when reconstructing a
    /// `WirePendingPatch` into its domain form.
    ///
    /// [`PatchDest`]: crate::core::primitives::PatchDest
    #[error("invalid pending patch destination: {source}")]
    InvalidPendingPatchDest {
        #[source]
        source: crate::core::primitives::PatchError,
    },
    /// Expanding `~/` or `$VAR` references in a patch source or policy
    /// pattern failed. Surfaces every failure mode of
    /// [`expand_source`](crate::core::expansion::expand_source): malformed
    /// syntax, a referenced var that is not in the resolved-vars set,
    /// or a post-expansion string that fails to parse as a glob.
    #[error("patch source expansion failed: {0}")]
    Expansion(#[from] crate::core::expansion::ExpandError),
    /// A pending var with an `Inherit`-shaped spec could not be
    /// resolved against the client's environment (e.g. the variable
    /// was absent and the spec had no `default`). Surfaces from
    /// `handle_response` when processing a daemon-emitted pending
    /// var.
    #[error("could not resolve pending var `{name}`: {source}")]
    VarResolution {
        /// The pending variable's name.
        name: String,
        /// The underlying env-lookup failure.
        #[source]
        source: std::env::VarError,
    },
}

/// Which policy domain a hook contract violation refers to. Keeps
/// the `HookContract` message constructors exhaustively dispatched
/// instead of stringly-typed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HookDomain {
    Var,
    Patch,
}

impl ComposeError {
    /// Build the `HookContract` variant fired when a hook returns
    /// `UseRule` for an item that the policy still can't decide
    /// after the hook's `updated_policy` is installed. `item_label`
    /// should already include any quoting the caller wants.
    pub(crate) fn use_rule_undecided(domain: HookDomain, item_label: String) -> Self {
        let kind = match domain {
            HookDomain::Var => "UseRule returned for a var the policy still cannot decide",
            HookDomain::Patch => "UseRule returned for a patch file the policy still cannot decide",
        };
        Self::HookContract {
            kind,
            context: item_label,
        }
    }

    /// Build the `HookContract` variant fired when the hook returns
    /// the wrong number of decisions for the batch.
    pub(crate) fn hook_decision_count_mismatch(
        domain: HookDomain,
        expected: usize,
        got: usize,
    ) -> Self {
        let kind = match domain {
            HookDomain::Var => "var-domain hook returned the wrong number of decisions",
            HookDomain::Patch => "patch-domain hook returned the wrong number of decisions",
        };
        Self::HookContract {
            kind,
            context: format!("expected {expected}, got {got}"),
        }
    }
}

/// Render a slice of `Display`-able errors as one indented bullet per
/// line, for embedding inside a parent error message.
struct DisplayJoin<'a, E: fmt::Display>(&'a [E]);

impl<E: fmt::Display> fmt::Display for DisplayJoin<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for e in self.0 {
            write!(f, "\n  - {e}")?;
        }
        Ok(())
    }
}

/// One environment variable that survived the policy gate.
///
/// A thin typestate wrapper over [`ProvenancedVar`] — same data, but
/// the type encodes that the contained var has been gated. The
/// distinction matters at API boundaries: a function taking
/// `&[SessionVar]` is documented to consume only post-gate items.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionVar(ProvenancedVar);

impl SessionVar {
    /// Direct construction. Crate-internal because outside callers
    /// should obtain `SessionVar`s by going through the gate (e.g.
    /// `UserComposer::compose`) or reconstructing one from a
    /// [`WireSessionVar`] via the `From` impl — both of which
    /// guarantee provenance is
    /// truthful. `pub(crate)` exposes it for in-crate handlers (e.g.
    /// `client::handler`) that build session vars from already-gated
    /// wire payloads.
    #[must_use]
    pub(crate) fn new(var: ResolvedVar, source: Source) -> Self {
        Self(ProvenancedVar::new(var, source))
    }

    /// Lift a [`ProvenancedVar`] that has passed the gate into a
    /// `SessionVar`. Zero-cost (no allocation, no clone).
    #[must_use]
    pub(crate) fn from_provenanced(pv: ProvenancedVar) -> Self {
        Self(pv)
    }

    /// The variable that survived the policy gate.
    #[must_use]
    pub fn var(&self) -> &ResolvedVar {
        self.0.var()
    }

    /// Consume the [`SessionVar`] and return `(var, source)`.
    #[must_use]
    pub fn into_parts(self) -> (ResolvedVar, Source) {
        self.0.into_parts()
    }
}

impl Provenanced for SessionVar {
    fn source(&self) -> &Source {
        self.0.source()
    }
}

impl crate::core::expansion::VarLookup for [SessionVar] {
    fn lookup(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|v| v.var().name() == name)
            .map(|v| v.var().value())
    }
}

impl From<WireSessionVar> for SessionVar {
    fn from(v: WireSessionVar) -> Self {
        Self::new(v.var.into(), v.source.into())
    }
}

/// One patch file that survived the policy gate, paired with its
/// origin. See [`SessionVar`] for the rationale.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionPatch {
    patch: ResolvedPatch,
    source: Source,
}

impl SessionPatch {
    /// The resolved patch — host source path plus the destination
    /// relative to the sandbox user's home directory.
    #[must_use]
    pub fn patch(&self) -> &ResolvedPatch {
        &self.patch
    }

    /// Consume the [`SessionPatch`] and return `(patch, source)`.
    #[must_use]
    pub fn into_parts(self) -> (ResolvedPatch, Source) {
        (self.patch, self.source)
    }
}

impl Provenanced for SessionPatch {
    fn source(&self) -> &Source {
        &self.source
    }
}

impl From<WireSessionPatch> for SessionPatch {
    fn from(p: WireSessionPatch) -> Self {
        Self {
            patch: p.patch.into(),
            source: p.source.into(),
        }
    }
}

/// One environment variable the daemon emitted as pending: id-tagged
/// for wire correlation, paired with the resolved domain
/// [`ProvenancedVar`] the client built from the wire spec + env.
///
/// Bridges wire and domain on the verdict-emitting side: the policy
/// check consumes the inner `ProvenancedVar`; the consuming
/// `into_*` methods on this type produce the matching
/// [`WireVarVerdict`] without extra clones.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PendingVar {
    id: PendingId,
    var: ProvenancedVar,
}

impl PendingVar {
    /// Build from a wire pending var by resolving its spec against
    /// `env`. Delegates to [`ResolvedVar::resolve_with`] for the
    /// env-handling logic so the rules stay in one place.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::VarResolution`] if the spec asks for
    /// an env lookup that fails (and `InheritWithDefault` can't
    /// recover via its default).
    pub(crate) fn from_wire(
        wire: WirePendingVar,
        env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
    ) -> Result<Self, ComposeError> {
        let resolved = ResolvedVar::resolve_with(wire.name, wire.spec.into(), env).map_err(
            |err| match err {
                VarError::ResolutionFailure { name, source } => {
                    ComposeError::VarResolution { name, source }
                }
                // `resolve_with` only ever emits `ResolutionFailure`.
                other => unreachable!("ResolvedVar::resolve_with returned {other:?}"),
            },
        )?;
        Ok(Self {
            id: wire.id,
            var: ProvenancedVar::new(resolved, wire.source.into()),
        })
    }

    /// Reassemble after the policy check hands the inner
    /// [`ProvenancedVar`] back (`Allowed`, `Denied`, or
    /// `NeedsApproval`). The id is supplied separately because the
    /// policy machinery doesn't know about it.
    #[must_use]
    pub(crate) fn reassemble(id: PendingId, var: ProvenancedVar) -> Self {
        Self { id, var }
    }

    /// Borrow the inner [`ProvenancedVar`]. Used to feed `policy.check`.
    #[must_use]
    pub(crate) fn provenanced(&self) -> &ProvenancedVar {
        &self.var
    }

    /// The variable's name.
    #[must_use]
    pub(crate) fn name(&self) -> &str {
        self.var.var().name()
    }

    /// Consume into `(id, ProvenancedVar)` for moves that the
    /// classifier needs to hand into `policy.check`.
    #[must_use]
    pub(crate) fn into_parts(self) -> (PendingId, ProvenancedVar) {
        (self.id, self.var)
    }

    /// Consume and emit an Approved verdict carrying the resolved
    /// name and value back to the daemon.
    #[must_use]
    pub(crate) fn into_approved_verdict(self) -> WireVarVerdict {
        let (resolved, _source) = self.var.into_parts();
        let (name, value) = resolved.into_parts();
        WireVarVerdict::Approved {
            id: self.id,
            value: WireResolvedVar { name, value },
        }
    }

    /// Consume and emit a Denied verdict.
    #[must_use]
    pub(crate) fn into_denied_verdict(self) -> WireVarVerdict {
        let (resolved, _source) = self.var.into_parts();
        let (name, _value) = resolved.into_parts();
        WireVarVerdict::Denied { id: self.id, name }
    }
}

/// One filesystem entry the daemon emitted as pending: id-tagged for
/// wire correlation, paired with the canonical [`PatchFile`] the
/// client's walker produced.
///
/// Bridges wire and domain on the patch verdict-emitting side, same
/// role as [`PendingVar`] does for vars.
pub(crate) struct PendingPatchFile {
    id: PendingId,
    file: PatchFile,
}

impl PendingPatchFile {
    #[must_use]
    pub(crate) fn new(id: PendingId, file: PatchFile) -> Self {
        Self { id, file }
    }

    /// Borrow the underlying file (e.g. to build an `Unapproved`
    /// view for hook prompts).
    #[must_use]
    pub(crate) fn file(&self) -> &PatchFile {
        &self.file
    }

    /// Consume into `(id, PatchFile)` so the classifier can hand the
    /// file into `policy.check`.
    #[must_use]
    pub(crate) fn into_parts(self) -> (PendingId, PatchFile) {
        (self.id, self.file)
    }

    /// Consume and emit an Approved verdict carrying the canonical
    /// target path back to the daemon.
    #[must_use]
    pub(crate) fn into_approved_verdict(self) -> WirePatchVerdict {
        WirePatchVerdict::Approved {
            id: self.id,
            host_path: self.file.target_path,
        }
    }

    /// Consume and emit a Denied verdict.
    #[must_use]
    pub(crate) fn into_denied_verdict(self) -> WirePatchVerdict {
        WirePatchVerdict::Denied {
            id: self.id,
            host_path: self.file.target_path,
        }
    }
}

/// Everything that survived the policy gate.
///
/// Vars and patches are policy-gated. Packages and lifecycle hooks
/// pass through unchanged — packages are graph-resolved downstream,
/// and hooks execute inside an isolated environment, so neither has a
/// policy in this layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Composition {
    vars: Vec<SessionVar>,
    patches: Vec<SessionPatch>,
    packages: Vec<ProvenancedPackage>,
    lifecycle_hooks: Vec<ProvenancedHook>,
}

impl Composition {
    /// The vars that survived the policy gate, each paired with its
    /// source.
    #[must_use]
    pub fn vars(&self) -> &[SessionVar] {
        &self.vars
    }

    /// The patches that survived the policy gate, each paired with its
    /// source. Multi-file patches appear as one [`SessionPatch`] per
    /// matched file.
    #[must_use]
    pub fn patches(&self) -> &[SessionPatch] {
        &self.patches
    }

    /// The packages contributed to the session, each paired with its
    /// source. Pass-through; no policy gate.
    #[must_use]
    pub fn packages(&self) -> &[ProvenancedPackage] {
        &self.packages
    }

    /// The lifecycle hooks contributed to the session, each paired
    /// with its source. Pass-through; no policy gate.
    #[must_use]
    pub fn lifecycle_hooks(&self) -> &[ProvenancedHook] {
        &self.lifecycle_hooks
    }

    /// Consume the [`Composition`] and return the underlying vectors
    /// for moving into downstream layers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<SessionVar>,
        Vec<SessionPatch>,
        Vec<ProvenancedPackage>,
        Vec<ProvenancedHook>,
    ) {
        (self.vars, self.patches, self.packages, self.lifecycle_hooks)
    }

    /// Append an already-gated wire contribution. The wire form has
    /// passed the user's policy on the client; items land verbatim.
    ///
    /// Atomic: if any item fails to convert, `self` is left unchanged
    /// and the error is returned.
    ///
    /// # Errors
    ///
    /// Surfaces [`ComposeError::InvalidWireItem`] if converting a
    /// contributed lifecycle hook hits the empty-hook case the domain
    /// type rejects.
    pub(crate) fn extend_from_wire(
        &mut self,
        wire: crate::wire::request::WireContribution,
    ) -> Result<(), ComposeError> {
        // Convert the fallible items up front so a failure on any one
        // leaves `self` untouched.
        let domain_hooks = wire
            .lifecycle_hooks
            .into_iter()
            .map(|wire_hook| {
                wire_hook
                    .try_into()
                    .map_err(|e| ComposeError::InvalidWireItem {
                        what: "lifecycle hook with no callbacks",
                        context: format!("{e}"),
                    })
            })
            .collect::<Result<Vec<ProvenancedHook>, _>>()?;

        self.vars
            .extend(wire.vars.into_iter().map(SessionVar::from));
        self.patches
            .extend(wire.patches.into_iter().map(SessionPatch::from));
        self.packages
            .extend(wire.requested_packages.into_iter().map(Into::into));
        self.lifecycle_hooks.extend(domain_hooks);
        Ok(())
    }
}

/// Configuration for the compose pipeline.
///
/// Defaults to symlink-safe behavior (no following) — appropriate for
/// dotfile trees where a symlink may legitimately point outside the
/// patch source.
#[derive(Clone, Copy, Debug, Default)]
pub struct ComposeOptions {
    /// If `true`, [`FileSet::resolve`](crate::core::primitives::FileSet::resolve)
    /// follows symlinks while walking patch sources. Off by default.
    pub follow_symlinks: bool,
}

// =====================================================================
// Per-domain gating
// =====================================================================

/// Invoke a var-domain hook on a batch of unapproved items. The
/// hook gets `policy` cloned (it can't mutate the caller's directly);
/// on success the caller gets back `(decisions, policy)` where
/// `policy` is the hook's `updated_policy` if it returned one, else
/// the original. Decision count is validated; mismatches return
/// `HookContract`.
///
/// Lifts the boilerplate (call hook, handle `Abort`, fold in
/// `updated_policy`, validate decision count) shared by [`gate_vars`]
/// (Phase 1 of `docs/COMPOSITION.md`) and
/// [`handle_response`](crate::client::handler::handle_response)
/// (Phase 3).
pub(crate) fn prompt_var_hook(
    hooks: &dyn PolicyHooks,
    policy: VarsPolicy,
    view: &[Unapproved<'_, str>],
) -> Result<(Vec<ItemDecision>, VarsPolicy), ComposeError> {
    match hooks.on_var_unapproved(policy.clone(), view) {
        HookResult::Abort => Err(ComposeError::Aborted),
        HookResult::Decided {
            decisions,
            updated_policy,
        } => {
            if decisions.len() != view.len() {
                return Err(ComposeError::hook_decision_count_mismatch(
                    HookDomain::Var,
                    view.len(),
                    decisions.len(),
                ));
            }
            Ok((decisions, updated_policy.unwrap_or(policy)))
        }
    }
}

/// Invoke a patch-domain hook on a batch of unapproved files. Same
/// shape as [`prompt_var_hook`], plus a `bool` indicating whether
/// the hook installed an `updated_policy` — the caller uses that
/// flag to decide whether to re-expand the policy's patterns against
/// the resolved vars.
pub(crate) fn prompt_patch_hook(
    hooks: &dyn PolicyHooks,
    policy: PatchPolicy,
    view: &[Unapproved<'_, camino::Utf8Path>],
) -> Result<(Vec<ItemDecision>, PatchPolicy, bool), ComposeError> {
    match hooks.on_patch_unapproved(policy.clone(), view) {
        HookResult::Abort => Err(ComposeError::Aborted),
        HookResult::Decided {
            decisions,
            updated_policy,
        } => {
            if decisions.len() != view.len() {
                return Err(ComposeError::hook_decision_count_mismatch(
                    HookDomain::Patch,
                    view.len(),
                    decisions.len(),
                ));
            }
            let (policy, updated) = match updated_policy {
                Some(new) => (new, true),
                None => (policy, false),
            };
            Ok((decisions, policy, updated))
        }
    }
}

/// Push, drop, or fail on a single [`Decision`].
///
/// Used by Pass 1 (categorizing every item) and by Pass 3's `UseRule`
/// branch (re-checking after the hook mutated the policy). The caller
/// supplies extractors for the `Denied` arm so the helper stays
/// agnostic to whether items are vars or patches.
pub(crate) fn apply_decision<T>(
    decision: Decision<T>,
    allowed: &mut Vec<T>,
    name_of: impl Fn(&T) -> String,
    source_of: impl Fn(T) -> Source,
) -> Result<(), ComposeError> {
    match decision {
        Decision::Allowed(t) => allowed.push(t),
        Decision::Ignored => {}
        Decision::Denied(t) => {
            let what = name_of(&t);
            return Err(ComposeError::Denied {
                what,
                from: source_of(t),
            });
        }
    }
    Ok(())
}

/// Drive the policy pass over a batch of vars.
///
/// `hooks` is `None` for user-only composition — all items are
/// expected to auto-decide. Any item that reaches the `NeedsApproval`
/// branch with no hook surfaces as [`ComposeError::HookRequired`].
pub(crate) fn gate_vars(
    items: Vec<ProvenancedVar>,
    mut policy: VarsPolicy,
    hooks: Option<&dyn PolicyHooks>,
) -> Result<(Vec<SessionVar>, VarsPolicy), ComposeError> {
    let name_of = |pv: &ProvenancedVar| pv.var().name().to_owned();
    let source_of = |pv: ProvenancedVar| pv.into_parts().1;

    // Pass 1: categorize.
    let mut allowed: Vec<ProvenancedVar> = Vec::new();
    let mut unapproved: Vec<ProvenancedVar> = Vec::new();
    for pv in items {
        let name = pv.var().name().to_owned();
        match policy.check(&name, pv) {
            CheckOutcome::Decided(d) => apply_decision(d, &mut allowed, name_of, source_of)?,
            CheckOutcome::NeedsApproval(pv) => unapproved.push(pv),
        }
    }
    if !unapproved.is_empty() {
        let Some(hooks) = hooks else {
            // Caller wired the user-only path but produced a
            // non-user-origin item that the policy couldn't decide.
            let pv = unapproved.into_iter().next().expect("non-empty");
            let what = name_of(&pv);
            return Err(ComposeError::HookRequired {
                what,
                from: source_of(pv),
            });
        };
        // Pass 2: prompt.
        let view: Vec<Unapproved<'_, str>> = unapproved
            .iter()
            .map(|pv| Unapproved {
                item: pv.var().name(),
                source: pv.source(),
            })
            .collect();
        let (decisions, new_policy) = prompt_var_hook(hooks, policy, &view)?;
        policy = new_policy;
        // Pass 3: apply.
        for (pv, decision) in unapproved.into_iter().zip(decisions) {
            match decision {
                ItemDecision::AllowOnce => allowed.push(pv),
                ItemDecision::UseRule => {
                    let name = pv.var().name().to_owned();
                    match policy.check(&name, pv) {
                        CheckOutcome::Decided(d) => {
                            apply_decision(d, &mut allowed, name_of, source_of)?;
                        }
                        CheckOutcome::NeedsApproval(pv) => {
                            return Err(ComposeError::use_rule_undecided(
                                HookDomain::Var,
                                format!("variable `{}`", pv.var().name()),
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok((
        allowed
            .into_iter()
            .map(SessionVar::from_provenanced)
            .collect(),
        policy,
    ))
}

/// Expand every patch's raw source string against `gated_vars` and
/// return the parallel list with `FileSet` sources. Fails fast on the
/// first [`ExpandError`](crate::core::expansion::ExpandError); a partial
/// expansion would let some patches reach the walker with their
/// references intact, which silently matches wrong paths.
pub(crate) fn expand_patch_sources(
    patches: Vec<ProvenancedPatch>,
    gated_vars: &[SessionVar],
    home_fallback: Option<&str>,
) -> Result<Vec<ExpandedProvenancedPatch>, ComposeError> {
    patches
        .into_iter()
        .map(|pp| {
            let (patch, provenance) = pp.into_parts();
            let source =
                crate::core::expansion::expand_source(patch.source(), gated_vars, home_fallback)?;
            Ok(ExpandedProvenancedPatch {
                source,
                dest: patch.dest().clone(),
                provenance,
            })
        })
        .collect()
}

/// Drive the policy pass over a batch of patches.
///
/// `hooks` is `None` for user-only composition — see [`gate_vars`].
pub(crate) fn gate_patches(
    items: Vec<ProvenancedPatch>,
    mut policy: PatchPolicy,
    hooks: Option<&dyn PolicyHooks>,
    options: ComposeOptions,
    gated_vars: &[SessionVar],
    home_fallback: Option<&str>,
) -> Result<(Vec<SessionPatch>, PatchPolicy), ComposeError> {
    let name_of = |pf: &PatchFile| pf.user_facing().as_str().to_owned();
    let source_of = |pf: PatchFile| pf.provenance;

    // Two policies in flight:
    //   - `policy` (raw): handed to the hook, returned to the caller —
    //     patterns retain their `~/` and `$VAR` form so the policy
    //     round-trips through serialization.
    //   - `expanded`: var-expanded copy used for the actual `check`
    //     calls — patterns actually match the absolute paths the
    //     walker yields. Re-derived whenever the hook updates the
    //     policy.
    //
    // Expand the *policy* first so a malformed pattern (undefined
    // `$VAR`, parent-dir traversal, etc.) surfaces before any
    // filesystem work happens. Otherwise a costly walk could complete
    // only to be discarded by a policy-expansion error the user has
    // no IO context for.
    let mut expanded = policy.expand_with(gated_vars, home_fallback)?;

    let expanded_patches = expand_patch_sources(items, gated_vars, home_fallback)?;
    let files = enumerate_patch_files(expanded_patches, options.follow_symlinks)?;

    // Pass 1: categorize per file.
    let mut allowed: Vec<PatchFile> = Vec::new();
    let mut unapproved: Vec<PatchFile> = Vec::new();
    for pf in files {
        let link = pf
            .link_path
            .as_ref()
            .map(|p| p.as_utf8_path().to_path_buf());
        let target = pf.target_path.as_utf8_path().to_path_buf();
        match expanded.check(link.as_deref(), &target, pf) {
            CheckOutcome::Decided(d) => apply_decision(d, &mut allowed, name_of, source_of)?,
            CheckOutcome::NeedsApproval(pf) => unapproved.push(pf),
        }
    }
    if !unapproved.is_empty() {
        let Some(hooks) = hooks else {
            let pf = unapproved.into_iter().next().expect("non-empty");
            let what = name_of(&pf);
            return Err(ComposeError::HookRequired {
                what,
                from: source_of(pf),
            });
        };
        // Pass 2: prompt.
        let view: Vec<Unapproved<'_, camino::Utf8Path>> = unapproved
            .iter()
            .map(|pf| Unapproved {
                item: pf.user_facing().as_utf8_path(),
                source: &pf.provenance,
            })
            .collect();
        let (decisions, new_policy, policy_updated) = prompt_patch_hook(hooks, policy, &view)?;
        policy = new_policy;
        if policy_updated {
            expanded = policy.expand_with(gated_vars, home_fallback)?;
        }
        // Pass 3: apply.
        for (pf, decision) in unapproved.into_iter().zip(decisions) {
            match decision {
                ItemDecision::AllowOnce => allowed.push(pf),
                ItemDecision::UseRule => {
                    let link = pf
                        .link_path
                        .as_ref()
                        .map(|p| p.as_utf8_path().to_path_buf());
                    let target = pf.target_path.as_utf8_path().to_path_buf();
                    match expanded.check(link.as_deref(), &target, pf) {
                        CheckOutcome::Decided(d) => {
                            apply_decision(d, &mut allowed, name_of, source_of)?;
                        }
                        CheckOutcome::NeedsApproval(pf) => {
                            return Err(ComposeError::use_rule_undecided(
                                HookDomain::Patch,
                                format!("source path `{}`", pf.user_facing()),
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok((
        allowed
            .into_iter()
            .map(|pf| SessionPatch {
                // `host_path` is the *canonical target* — that's where
                // the content actually lives. `dest` is computed from
                // the user-facing (link if distinct, target otherwise)
                // path's relationship to the walk root, so the user's
                // structural intent is preserved.
                patch: ResolvedPatch::new(pf.target_path, pf.dest),
                source: pf.provenance,
            })
            .collect(),
        policy,
    ))
}

/// Compose a populated [`Contribution`] into a [`Composition`].
///
/// The shared core of both composers: applies the policy, drives any
/// needed hook prompts (when `hooks` is `Some`), runs patch expansion
/// against the resolved vars, and assembles the final structure.
///
/// # Errors
///
/// See [`ComposeError`].
pub(crate) fn compose_contribution(
    contribution: Contribution,
    expansion_vars: &[SessionVar],
    policy: UserPolicy,
    hooks: Option<&dyn PolicyHooks>,
    options: ComposeOptions,
    home_fallback: Option<&str>,
) -> Result<(Composition, UserPolicy), ComposeError> {
    let Contribution {
        vars,
        patches,
        packages,
        lifecycle_hooks,
    } = contribution;
    let (vars_policy, patches_policy) = policy.into_parts();
    let (gated_vars, vars_policy) = gate_vars(vars, vars_policy, hooks)?;
    // Patch sources and policy patterns expand against the resolved
    // vars. Explicit `$VAR` references require an explicit
    // `SessionVar` — no env fallback. The tilde prefix (`~/...`) is
    // the one exception: it falls back to `home_fallback` if the
    // loadout didn't declare a `HOME` var.
    //
    // `expansion_vars` carries pre-gated vars from an outer scope
    // (e.g. the client's wire contribution as seen by the daemon)
    // so daemon-side patches can resolve `$VAR` / `~` against them.
    // They precede locally-gated vars in the lookup so the
    // user-side declaration wins on conflict.
    let combined_for_lookup: Vec<SessionVar> = expansion_vars
        .iter()
        .cloned()
        .chain(gated_vars.iter().cloned())
        .collect();
    let (gated_patches, patches_policy) = gate_patches(
        patches,
        patches_policy,
        hooks,
        options,
        &combined_for_lookup,
        home_fallback,
    )?;
    let final_policy = UserPolicy::empty()
        .with_vars(vars_policy)
        .with_patches(patches_policy);
    let composition = Composition {
        vars: gated_vars,
        patches: gated_patches,
        packages,
        lifecycle_hooks,
    };
    Ok((composition, final_policy))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
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
            path: paths::HostPath::new("/repo"),
        }
    }

    fn pv_with(name: &str, source: Source) -> ProvenancedVar {
        ProvenancedVar::new(
            ResolvedVar::resolve_with(name.into(), VarValue::specified("x"), |_| {
                Err(std::env::VarError::NotPresent)
            })
            .unwrap(),
            source,
        )
    }

    fn pv(name: &str) -> ProvenancedVar {
        pv_with(name, project_source())
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
            _policy: PatchPolicy,
            _items: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchPolicy> {
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
            _: PatchPolicy,
            _: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchPolicy> {
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
            _: PatchPolicy,
            items: &[Unapproved<'_, camino::Utf8Path>],
        ) -> HookResult<PatchPolicy> {
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
    // Vars gating
    // =================================================================

    mod vars_gating {
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
            let policy = PatchPolicy::empty();
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].source(), &user_source());
        }

        #[test]
        fn project_origin_goes_through_prompt() {
            let (_tmp, patch) = single_file_patch("conf.toml", "etc/conf.toml");
            let pp = ProvenancedPatch::new(patch, project_source());
            let policy = PatchPolicy::empty();
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PassThroughHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].source(), &project_source());
        }

        #[test]
        fn deny_via_policy_errors() {
            let (_tmp, patch) = single_file_patch("secret.pem", "config/x");
            let pp = ProvenancedPatch::new(patch, project_source());
            let policy = PatchPolicy::empty().with_deny(["/**/*.pem"]);
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PassThroughHook),
                ComposeOptions::default(),
                &[],
                None,
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
            let policy = PatchPolicy::empty().with_deny(["/**/*.pem"]);
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
        }

        #[test]
        fn user_loadout_still_honors_ignore() {
            let (_tmp, patch) = single_file_patch("trash.bak", "config/x");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_ignore(["/**/*.bak"]);
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert!(resolved.is_empty());
        }

        /// Build a [`SessionVar`] for tests where the gating step expects
        /// a value to substitute into `$VAR` or `~/` references.
        fn home_var(value: &str) -> SessionVar {
            let resolved =
                ResolvedVar::resolve_with("HOME".into(), VarValue::specified(value), |_| {
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
            let policy = PatchPolicy::empty();
            let (mut resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap();
            resolved.sort_by_key(|sp| sp.patch().destination().as_str().to_owned());
            let dests: Vec<_> = resolved
                .iter()
                .map(|sp| sp.patch().destination().as_str())
                .collect();
            assert_eq!(dests, ["nvim/a.lua", "nvim/sub/b.lua"]);
        }

        #[test]
        fn walk_failure_surfaces_as_patch_walk() {
            let patch = Patch::new(
                "/definitely/does/not/exist/*",
                PatchDest::try_new("x").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(err, ComposeError::PatchWalk { ref sources } if !sources.is_empty()),
                "got: {err:?}",
            );
        }

        #[test]
        fn tilde_pattern_with_missing_home_var_errors() {
            let patch = Patch::new("~/dotfiles/conf", PatchDest::try_new("conf").unwrap());
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
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
            let policy = PatchPolicy::empty();
            let vars = [home_var(root.as_str())];
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &vars,
                None,
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

            let policy = PatchPolicy::empty().with_deny(["~/.ssh/**"]);
            let vars = [home_var(root.as_str())];

            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PassThroughHook),
                ComposeOptions::default(),
                &vars,
                None,
            )
            .unwrap_err();
            assert!(matches!(err, ComposeError::Denied { .. }), "got: {err:?}");
        }

        #[test]
        fn policy_tilde_pattern_without_home_var_errors() {
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_deny(["~/.ssh/**"]);
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
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
        fn user_prefixed_tilde_is_rejected_as_relative() {
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_deny(["~someuser/.ssh/**"]);
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ComposeError::Expansion(
                        crate::core::expansion::ExpandError::NotAbsolute { .. }
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

            let policy = PatchPolicy::empty().with_allow(["~/.config/**"]);
            let vars = [home_var(root.as_str())];

            let (_resolved, policy_out) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &vars,
                None,
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
                    policy: PatchPolicy,
                    items: &[Unapproved<'_, camino::Utf8Path>],
                ) -> HookResult<PatchPolicy> {
                    let updated = policy.with_deny(["~/*.pem"]);
                    HookResult::decided_with_policy(
                        vec![ItemDecision::UseRule; items.len()],
                        updated,
                    )
                }
            }

            let tmp = tempfile::tempdir().unwrap();
            let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
            let file = root.join("secret.pem");
            std::fs::write(file.as_std_path(), "x").unwrap();

            let patch = Patch::new(file.as_str(), PatchDest::try_new("secret.pem").unwrap());
            let pp = ProvenancedPatch::new(patch, project_source());

            let policy = PatchPolicy::empty();
            let vars = [home_var(root.as_str())];

            let err = gate_patches(
                vec![pp],
                policy,
                Some(&TildeDenyAddingHook),
                ComposeOptions::default(),
                &vars,
                None,
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
                    policy: PatchPolicy,
                    items: &[Unapproved<'_, camino::Utf8Path>],
                ) -> HookResult<PatchPolicy> {
                    let updated = policy.with_deny(["$NOT_RESOLVED/*"]);
                    HookResult::decided_with_policy(
                        vec![ItemDecision::UseRule; items.len()],
                        updated,
                    )
                }
            }
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, project_source());
            let policy = PatchPolicy::empty();
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&UnknownVarHook),
                ComposeOptions::default(),
                &[],
                None,
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
            let policy = PatchPolicy::empty();
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions {
                    follow_symlinks: true,
                },
                &[],
                None,
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
            let policy = PatchPolicy::empty().with_deny([format!("{denied_dir}/**")]);
            let err = gate_patches(
                vec![pp],
                policy,
                Some(&PassThroughHook),
                ComposeOptions {
                    follow_symlinks: true,
                },
                &[],
                None,
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
            let policy = PatchPolicy::empty().with_allow([format!("{root}/**")]);
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions {
                    follow_symlinks: true,
                },
                &[],
                None,
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

            let policy = PatchPolicy::empty().with_allow([format!("{link}/**")]);
            let (resolved, _) = gate_patches(
                vec![pp],
                policy,
                Some(&PanicHook),
                ComposeOptions::default(),
                &[],
                None,
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
    }

    // =================================================================
    // Composition::extend_from_wire
    // =================================================================

    mod extend_from_wire {
        use super::*;
        use crate::wire::primitives::{
            WireLifecycleHook, WirePackageRef, WireProvenancedHook, WireResolvedVar,
            WireSessionVar, WireSource,
        };
        use crate::wire::request::WireContribution;

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
    }
}
