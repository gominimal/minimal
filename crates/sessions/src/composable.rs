use core::fmt;

use camino::{Utf8Path, Utf8PathBuf};

use paths::{HostAbsPath, HostPath, SandboxRelPath};

use crate::{
    patches::{Patch, PatchPolicy, ResolvedPatch},
    policy::UserPolicy,
    vars::{ResolvedVar, VarsPolicy},
};

/// Errors produced while composing a [`Composable`] into a [`Composer`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A variable declaration failed validation or resolution.
    #[error("variable contribution failed: {source}")]
    Var {
        #[from]
        source: crate::vars::Error,
    },
    /// A patch declaration failed validation.
    #[error("patch contribution failed: {source}")]
    Patch {
        #[from]
        source: crate::patches::Error,
    },
    /// A lifecycle hook declaration failed validation.
    #[error("lifecycle hook contribution failed: {source}")]
    LifecycleHook {
        #[from]
        source: crate::lifecyclehook::Error,
    },
}

/// Where a contribution came from — the provenance attached to every
/// item that flows through the resolver.
///
/// `Source` is what makes the user-origin bypass possible
/// ([`VarsPolicy::check`](crate::vars::VarsPolicy::check) /
/// [`PatchPolicy::check`](crate::patches::PatchPolicy::check) inspect
/// this) and what error messages name when an item is rejected.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The user's own [`Loadout`](crate::loadout::Loadout). Bypasses
    /// `allow`/`deny` checks (only `ignore` still applies).
    UserLoadout { name: String },
    /// A project's `minimal.toml`, identified by the path of the
    /// config file.
    Project { path: HostPath },
    /// A specific package's declaration, identified by package name.
    Package { name: String },
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserLoadout { name } => write!(f, "user loadout `{name}`"),
            Self::Project { path } => write!(f, "project `{path}`"),
            Self::Package { name } => write!(f, "package `{name}`"),
        }
    }
}

/// Trait for types that know which [`Source`] contributed them.
///
/// The resolver takes `T: Provenanced` so policy `check` methods can
/// query the source without the caller having to thread it through
/// alongside the item.
pub trait Provenanced {
    /// The [`Source`] this item came from.
    fn source(&self) -> &Source;
}

/// A [`ResolvedVar`] tagged with its [`Source`] for the resolver.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedVar {
    var: ResolvedVar,
    source: Source,
}

impl ProvenancedVar {
    /// Construct a [`ProvenancedVar`] from a resolved variable and its
    /// origin.
    #[must_use]
    pub fn new(var: ResolvedVar, source: Source) -> Self {
        Self { var, source }
    }

    /// The wrapped [`ResolvedVar`].
    #[must_use]
    pub fn var(&self) -> &ResolvedVar {
        &self.var
    }
}

impl Provenanced for ProvenancedVar {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A [`Patch`] tagged with its [`Source`] for the resolver.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedPatch {
    patch: Patch,
    source: Source,
}

impl ProvenancedPatch {
    /// Construct a [`ProvenancedPatch`] from a patch declaration and
    /// its origin.
    #[must_use]
    pub fn new(patch: Patch, source: Source) -> Self {
        Self { patch, source }
    }

    /// The wrapped [`Patch`].
    #[must_use]
    pub fn patch(&self) -> &Patch {
        &self.patch
    }
}

impl Provenanced for ProvenancedPatch {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A package name tagged with its [`Source`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedPackage {
    package: String,
    source: Source,
}

impl ProvenancedPackage {
    /// Construct a [`ProvenancedPackage`] from a package name and its
    /// origin.
    #[must_use]
    pub fn new(package: impl Into<String>, source: Source) -> Self {
        Self {
            package: package.into(),
            source,
        }
    }

    /// The package name (typically the form `name@version` used to
    /// identify a package in the graph).
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }
}

impl Provenanced for ProvenancedPackage {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A [`LifecycleHook`](crate::lifecyclehook::LifecycleHook) tagged with
/// its [`Source`].
///
/// Lifecycle hooks run inside the sandbox (or its equivalent isolated
/// environment), so they don't go through the policy gate — they
/// pass through resolution unchanged.
#[derive(Clone, Debug)]
pub struct ProvenancedHook {
    hook: crate::lifecyclehook::LifecycleHook,
    source: Source,
}

impl ProvenancedHook {
    /// Construct a [`ProvenancedHook`] from a hook declaration and its
    /// origin.
    #[must_use]
    pub fn new(hook: crate::lifecyclehook::LifecycleHook, source: Source) -> Self {
        Self { hook, source }
    }

    /// The wrapped [`LifecycleHook`](crate::lifecyclehook::LifecycleHook).
    #[must_use]
    pub fn hook(&self) -> &crate::lifecyclehook::LifecycleHook {
        &self.hook
    }
}

impl Provenanced for ProvenancedHook {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A single source's contribution to a session, materialized as a
/// concrete value rather than streamed into a [`Composer`].
///
/// Returned by [`Composable::contribute`]. The composer drains
/// `Contribution`s as it accumulates them — the indirection through
/// this struct keeps the boundary between contributor and composer
/// crisp:
///
/// - **Contributors** build a `Contribution` (often with the builder
///   methods) and hand it back. They don't need any access to
///   [`Composer`] internals.
/// - **Tests** can verify a contributor's output in isolation
///   (`loadout.contribute()` returns the same `Contribution` regardless
///   of which composer it's fed into).
/// - **The composer** owns the merge step in one place — useful when
///   conflict-resolution semantics are added later.
#[derive(Clone, Debug, Default)]
pub struct Contribution {
    vars: Vec<ProvenancedVar>,
    patches: Vec<ProvenancedPatch>,
    packages: Vec<ProvenancedPackage>,
    lifecycle_hooks: Vec<ProvenancedHook>,
}

impl Contribution {
    /// Construct an empty contribution.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a var (builder style).
    #[must_use]
    pub fn with_var(mut self, v: ProvenancedVar) -> Self {
        self.vars.push(v);
        self
    }

    /// Append a patch (builder style).
    #[must_use]
    pub fn with_patch(mut self, p: ProvenancedPatch) -> Self {
        self.patches.push(p);
        self
    }

    /// Append a package (builder style).
    #[must_use]
    pub fn with_package(mut self, p: ProvenancedPackage) -> Self {
        self.packages.push(p);
        self
    }

    /// Append a lifecycle hook (builder style).
    #[must_use]
    pub fn with_hook(mut self, h: ProvenancedHook) -> Self {
        self.lifecycle_hooks.push(h);
        self
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

/// A lookup function for resolving inherited environment variables.
///
/// Threaded through [`Composable::contribute`] so var declarations
/// with `inherit = true` (or `InheritWithDefault`) can be resolved
/// against an arbitrary environment — production callers pass
/// [`std::env::var`]; tests pass a synthetic closure.
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Result<String, std::env::VarError>;

/// Anything that can contribute primitives (vars, patches, packages,
/// lifecycle hooks) to a [`Composer`] during session construction.
///
/// Implementors are user-curated sources of session state — loadouts,
/// project configs, and package specs. The trait is the funnel that
/// brings their declarations into one place to be resolved against the
/// user's [`UserPolicy`].
///
/// The trait does *not* require [`Provenanced`]: a contributor isn't
/// itself an "item" — it's the *source* of items. Each contributor
/// knows its own [`Source`] and tags its primitives accordingly.
pub trait Composable {
    /// Produce this source's [`Contribution`].
    ///
    /// Consuming `self` matches the one-shot nature of contribution:
    /// each contributor is "spent" once it hands off its primitives.
    /// `env` resolves any inherited variables the contributor needs to
    /// materialize.
    ///
    /// # Errors
    ///
    /// Implementations return an [`Error`] when their primitives fail
    /// their own construction-time validation (e.g. an invalid glob,
    /// an empty patch destination, or an env lookup that surfaced an
    /// error).
    fn contribute(self, env: EnvLookup<'_>) -> Result<Contribution, Error>;
}

// =====================================================================
// Resolution: deciding what survives the user's policy
// =====================================================================

/// What the policy decided about a single item.
///
/// `Ignored` carries no payload — the caller silently drops the item.
/// `Allowed` and `Denied` carry the item through so callers can collect
/// it (or, in the case of `Denied`, name it in the error).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Decision<T> {
    /// The item passes the policy and should be included.
    Allowed(T),
    /// The item matches an `ignore` rule and should be silently dropped.
    Ignored,
    /// The item is explicitly forbidden; session construction aborts.
    Denied(T),
}

/// The outcome of a single policy `check`.
///
/// `NeedsApproval` hands the item back so the resolve loop can prompt
/// for it via a [`PolicyHooks`] callback and re-check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CheckOutcome<T> {
    /// The policy reached a verdict on its own.
    Decided(Decision<T>),
    /// No rule matched; the item must be referred to a [`PolicyHooks`]
    /// callback for an application-level decision.
    NeedsApproval(T),
}

/// One item the policy could not decide. The item is held by reference
/// so the resolve loop retains ownership for the second pass.
///
/// Constructed only by the resolver; hooks receive these as borrowed
/// slices. The fields are inaccessible to outside code on purpose —
/// nothing prevents constructing one, but the lifetimes are tied to
/// the resolver's frame and there's no sensible way to manufacture
/// matched references elsewhere.
#[derive(Clone, Debug)]
pub struct Unapproved<'a, T: ?Sized> {
    item: &'a T,
    source: &'a Source,
}

impl<'a, T: ?Sized> Unapproved<'a, T> {
    /// The item the policy couldn't decide on (e.g. a variable name or
    /// patch source path).
    #[must_use]
    pub fn item(&self) -> &'a T {
        self.item
    }

    /// The [`Source`] that contributed this item — useful for prompts
    /// like "project `~/foo` wants to set `AWS_KEY`."
    #[must_use]
    pub fn source(&self) -> &'a Source {
        self.source
    }
}

/// One application-supplied decision per `Unapproved` item, returned by
/// a [`PolicyHooks`] callback in the same order the items were given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ItemDecision {
    /// Approve this item without recording a rule.
    AllowOnce,
    /// Reject this item without recording a rule.
    DenyOnce,
    /// Re-check against the (possibly mutated) policy.
    UseRule,
}

/// The hook's response to the batch of unapproved items.
///
/// Hooks **cannot** mutate the policy directly. If the application
/// updates the policy in response to the prompt, it returns the updated
/// copy in `updated_policy`. `None` means "no rule changes." The
/// resolver installs `updated_policy` (if `Some`) before re-checking
/// any `UseRule` decisions in this batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookResult<P> {
    /// Per-item decisions, indexed parallel to the input slice, plus
    /// an optional updated policy snapshot.
    Decided {
        decisions: Vec<ItemDecision>,
        updated_policy: Option<P>,
    },
    /// User chose to abort session construction.
    Abort,
}

impl<P> HookResult<P> {
    /// Construct a [`Decided`](Self::Decided) result that leaves the
    /// policy unchanged.
    #[must_use]
    pub fn decided(decisions: Vec<ItemDecision>) -> Self {
        Self::Decided {
            decisions,
            updated_policy: None,
        }
    }

    /// Construct a [`Decided`](Self::Decided) result that installs a
    /// new policy snapshot.
    #[must_use]
    pub fn decided_with_policy(decisions: Vec<ItemDecision>, updated_policy: P) -> Self {
        Self::Decided {
            decisions,
            updated_policy: Some(updated_policy),
        }
    }

    /// Construct an [`Abort`](Self::Abort) result.
    #[must_use]
    pub fn abort() -> Self {
        Self::Abort
    }
}

/// Application-supplied hooks for handling items the policy couldn't
/// decide on its own.
///
/// Hooks receive an owned copy of the *narrow* domain policy
/// (`VarsPolicy` / `PatchPolicy`); they cannot mutate the resolver's
/// state directly. To add rules, return a modified policy snapshot in
/// [`HookResult::Decided::updated_policy`] — wider mutations to the
/// full [`UserPolicy`] are not exposed here.
///
/// # `~` in returned patch policies
///
/// Patch-policy patterns are stored verbatim and round-trip losslessly.
/// When a hook adds (or modifies) a patch-policy rule with a leading
/// `~`, return it in `~`-form — the resolver re-expands the policy
/// internally for matching, while the returned policy keeps the raw
/// form so the caller can persist it. Do **not** expand `~` inside the
/// hook; double-resolution will produce wrong matches.
///
/// Vars policies have no analogous `~`-expansion concern: variable
/// names are not paths, so the home directory is not relevant on the
/// vars side.
pub trait PolicyHooks {
    fn on_var_unapproved(
        &self,
        policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy>;

    fn on_patch_unapproved(
        &self,
        policy: PatchPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchPolicy>;
}

/// Errors raised by the resolution pass.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
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
    /// One or more patch source filesystem walks failed with IO-level
    /// errors (permission denied, non-UTF-8 paths, etc.). All errors
    /// surfaced by every `FileSet::resolve` invocation are accumulated
    /// — none are discarded.
    #[error("patch resolution failed ({} error(s)):{}", sources.len(), DisplayJoin(sources))]
    PatchWalk { sources: Vec<crate::patches::Error> },
    /// Expanding `~/` or `$VAR` references in a patch source or policy
    /// pattern failed. Surfaces every failure mode of
    /// [`expand_source`](crate::expansion::expand_source): malformed
    /// syntax, a referenced var that is not in the resolved-vars set,
    /// or a post-expansion string that fails to parse as a glob.
    #[error("patch source expansion failed: {0}")]
    Expansion(#[from] crate::expansion::ExpandError),
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

/// One environment variable that survived policy resolution, paired
/// with its origin.
///
/// The source is retained so downstream layers (CLI inspection, audit
/// logs, error reporting) can attribute each decision back to the
/// contributor that asked for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionVar {
    var: ResolvedVar,
    source: Source,
}

impl SessionVar {
    /// Construct directly. Outside the resolver, the only callers
    /// expected to use this are tests building synthetic sessions.
    #[cfg(test)]
    #[must_use]
    pub fn new(var: ResolvedVar, source: Source) -> Self {
        Self { var, source }
    }

    /// The resolved variable that survived policy resolution.
    #[must_use]
    pub fn var(&self) -> &ResolvedVar {
        &self.var
    }
}

impl Provenanced for SessionVar {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// One patch file that survived policy resolution, paired with its
/// origin. See [`SessionVar`] for the rationale.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl Provenanced for SessionPatch {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// Everything that survived policy resolution.
///
/// Vars and patches are policy-gated. Packages and lifecycle hooks
/// pass through unchanged — packages are graph-resolved downstream,
/// and hooks execute inside an isolated environment, so neither has a
/// policy in this layer.
#[derive(Clone, Debug, Default)]
pub struct Resolution {
    vars: Vec<SessionVar>,
    patches: Vec<SessionPatch>,
    packages: Vec<ProvenancedPackage>,
    lifecycle_hooks: Vec<ProvenancedHook>,
}

impl Resolution {
    /// The vars that survived resolution, each paired with its source.
    #[must_use]
    pub fn vars(&self) -> &[SessionVar] {
        &self.vars
    }

    /// The patches that survived resolution, each paired with its
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

    /// Consume the [`Resolution`] and return the underlying vectors
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
}

/// A [`crate::patches::PatchPolicy`] with all `~/` and `$VAR`
/// references expanded into concrete glob patterns against a set of
/// resolved session vars.
///
/// Produced from a raw [`crate::patches::PatchPolicy`] via
/// [`crate::patches::PatchPolicy::expand_with`] at the resolver's
/// main entry point; the resolver matches against this form, not the
/// raw policy. The raw policy is preserved separately so it can
/// round-trip through serialization unchanged.
#[derive(Clone, Debug)]
pub struct ExpandedPatchPolicy {
    allow: Vec<crate::patches::FileSet>,
    deny: Vec<crate::patches::FileSet>,
    ignore: Vec<crate::patches::FileSet>,
}

impl ExpandedPatchPolicy {
    /// Construct an `ExpandedPatchPolicy` directly from already-expanded
    /// pattern lists.
    ///
    /// This constructor is `pub(crate)` because the only legitimate
    /// way to produce an [`ExpandedPatchPolicy`] from outside this
    /// crate is via [`crate::patches::PatchPolicy::expand_with`] — the
    /// type's whole job is to be the validated-and-expanded form of a
    /// raw policy. Exposing a public constructor (or `with_*` setters)
    /// would let callers smuggle arbitrary `FileSet`s past the
    /// expansion step and bypass the round-trip guarantee documented
    /// on [`crate::patches::PatchPolicy`].
    ///
    /// Order is positional. Inside this crate the only caller is
    /// `expand_with`, which threads each list explicitly; if more
    /// callers appear, switch back to a builder.
    pub(crate) fn from_expanded(
        allow: Vec<crate::patches::FileSet>,
        deny: Vec<crate::patches::FileSet>,
        ignore: Vec<crate::patches::FileSet>,
    ) -> Self {
        Self {
            allow,
            deny,
            ignore,
        }
    }

    /// Expanded `allow` patterns.
    #[must_use]
    pub fn allow(&self) -> &[crate::patches::FileSet] {
        &self.allow
    }

    /// Expanded `deny` patterns.
    #[must_use]
    pub fn deny(&self) -> &[crate::patches::FileSet] {
        &self.deny
    }

    /// Expanded `ignore` patterns.
    #[must_use]
    pub fn ignore(&self) -> &[crate::patches::FileSet] {
        &self.ignore
    }

    /// Categorize a file against this expanded policy.
    ///
    /// `target` is the canonical host path the file resolves to (what
    /// I/O will actually touch). `link` is `Some` only when symlink
    /// resolution produced a distinct path — i.e. the walker
    /// traversed an actual symlink. Both forms are checked
    /// independently and the outcomes are combined.
    ///
    /// **Precedence within one path:** `ignore` first, then a
    /// source-aware branch. For user-origin items
    /// ([`Source::UserLoadout`]), `allow` and `deny` do not apply —
    /// anything not ignored is implicitly allowed. For every other
    /// source, the precedence continues `deny` → `allow` →
    /// `NeedsApproval`.
    ///
    /// **Combination precedence:** `Denied` > `Ignored` >
    /// `NeedsApproval` > `Allowed`. Any deny on either path wins
    /// (security first); no deny but an ignore on either path drops
    /// the file; otherwise any prompt wins; both must independently
    /// `Allowed` for the file to pass cleanly. When `link` is
    /// `None` only the target is checked.
    ///
    /// Cost: one or two [`decide`](Self::decide) calls; each scans up
    /// to three pattern lists (`ignore`, `deny`, `allow`). Fine at
    /// typical patch counts.
    #[must_use]
    pub fn check<T: Provenanced>(
        &self,
        link: Option<&camino::Utf8Path>,
        target: &camino::Utf8Path,
        item: T,
    ) -> CheckOutcome<T> {
        let source = item.source();
        let target_decision = self.decide(target, source);
        let combined = match link {
            Some(l) => self.decide(l, source).combine(target_decision),
            None => target_decision,
        };
        attach_decision(combined, item)
    }

    /// Path-only decision; no item ownership involved. Internal
    /// helper used by both [`check`](Self::check) and
    /// [`check_dual`](Self::check_dual).
    fn decide(&self, path: &camino::Utf8Path, source: &Source) -> PathDecision {
        if filesets_match(&self.ignore, path) {
            return PathDecision::Ignored;
        }
        if matches!(source, Source::UserLoadout { .. }) {
            return PathDecision::Allowed;
        }
        if filesets_match(&self.deny, path) {
            PathDecision::Denied
        } else if filesets_match(&self.allow, path) {
            PathDecision::Allowed
        } else {
            PathDecision::NeedsApproval
        }
    }
}

/// Path-level decision used internally by
/// [`ExpandedPatchPolicy::decide`]. The public-facing outcome
/// ([`CheckOutcome`]) carries the item; this type doesn't, so it can
/// be computed for the same item against multiple paths and combined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathDecision {
    Allowed,
    Ignored,
    Denied,
    NeedsApproval,
}

impl PathDecision {
    /// Combine two per-path decisions into one. Precedence (most
    /// restrictive first):
    /// `Denied` > `Ignored` > `NeedsApproval` > `Allowed`.
    fn combine(self, other: Self) -> Self {
        use PathDecision::{Allowed, Denied, Ignored, NeedsApproval};
        if self == Denied || other == Denied {
            return Denied;
        }
        if self == Ignored || other == Ignored {
            return Ignored;
        }
        if self == NeedsApproval || other == NeedsApproval {
            return NeedsApproval;
        }
        Allowed
    }
}

fn attach_decision<T>(decision: PathDecision, item: T) -> CheckOutcome<T> {
    match decision {
        PathDecision::Allowed => CheckOutcome::Decided(Decision::Allowed(item)),
        PathDecision::Ignored => CheckOutcome::Decided(Decision::Ignored),
        PathDecision::Denied => CheckOutcome::Decided(Decision::Denied(item)),
        PathDecision::NeedsApproval => CheckOutcome::NeedsApproval(item),
    }
}

fn filesets_match(sets: &[crate::patches::FileSet], path: &camino::Utf8Path) -> bool {
    sets.iter().any(|fs| fs.is_match(path))
}

/// Configuration for [`Composer::resolve`].
///
/// Defaults to symlink-safe behavior (no following) — appropriate for
/// dotfile trees where a symlink may legitimately point outside the
/// patch source.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolveOptions {
    /// If `true`, [`FileSet::resolve`](crate::patches::FileSet::resolve)
    /// follows symlinks while walking patch sources. Off by default.
    pub follow_symlinks: bool,
}

// =====================================================================
// Composer
// =====================================================================

/// Accumulator for contributions from one or more [`Composable`]
/// sources, drained by [`Composer::resolve`] into a [`Resolution`].
///
/// Contributors push vars and patches; the composer does no policy
/// work until `resolve` is called. This separates declarative
/// accumulation from the (potentially interactive) resolution pass.
/// Boxed env-lookup closure stored in [`Composer`].
///
/// `Send + Sync` so [`Composer`] itself is `Send + Sync` and can be
/// built on one thread and resolved on another (e.g. async server
/// handing the composer off to a worker pool). Closures captured by
/// [`Composer::with_env`] must satisfy the bound; the defaults
/// (function pointers like `std::env::var`) trivially do.
type StoredEnv = Box<dyn Fn(&str) -> Result<String, std::env::VarError> + Send + Sync>;

pub struct Composer {
    vars: Vec<ProvenancedVar>,
    patches: Vec<ProvenancedPatch>,
    packages: Vec<ProvenancedPackage>,
    lifecycle_hooks: Vec<ProvenancedHook>,
    env: StoredEnv,
}

impl fmt::Debug for Composer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Composer")
            .field("vars", &self.vars)
            .field("patches", &self.patches)
            .field("packages", &self.packages)
            .field("lifecycle_hooks", &self.lifecycle_hooks)
            .field("env", &"<closure>")
            .finish()
    }
}

impl Default for Composer {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time guarantee: `Composer` is `Send + Sync`. If a future
// change to a field (or to one of the stored-closure type aliases)
// removes either auto-trait, this assertion fails at compile time
// and the offending field is named in the error.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Composer>();
};

impl Composer {
    /// Construct an empty composer with the default env lookup
    /// ([`std::env::var`]). Suitable for production code.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vars: Vec::new(),
            patches: Vec::new(),
            packages: Vec::new(),
            lifecycle_hooks: Vec::new(),
            env: Box::new(|name| std::env::var(name)),
        }
    }

    /// Replace the env lookup. Useful for tests that want to pin env
    /// behavior without touching the process environment.
    #[must_use]
    pub fn with_env(mut self, env: StoredEnv) -> Self {
        self.env = env;
        self
    }

    /// Take a [`Composable`]'s contribution and merge it into this
    /// composer. The canonical entry point for populating a composer.
    ///
    /// # Errors
    ///
    /// Returns any error the contributor surfaces from [`Composable::contribute`].
    pub fn add(&mut self, c: impl Composable) -> Result<(), Error> {
        self.merge(c.contribute(&*self.env)?);
        Ok(())
    }

    /// Add every [`Composable`] in `items` in order. Stops at the
    /// first failure and returns that error.
    ///
    /// # Errors
    ///
    /// Returns the first [`Error`] surfaced by any contributor.
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

    /// Drain a [`Contribution`] into the composer.
    ///
    /// This is the single internal merge step — when conflict
    /// resolution lands, it lives here. Today: pure aggregation, no
    /// dedup / no merge policy.
    fn merge(&mut self, mut c: Contribution) {
        self.vars.append(&mut c.vars);
        self.patches.append(&mut c.patches);
        self.packages.append(&mut c.packages);
        self.lifecycle_hooks.append(&mut c.lifecycle_hooks);
    }

    /// Resolve every accumulated contribution against `policy`.
    ///
    /// Invokes `hooks` once per domain to handle items the policy
    /// couldn't decide; hooks may return updated policy snapshots
    /// mid-flight. The (possibly updated) [`UserPolicy`] is returned
    /// alongside the [`Resolution`] so callers can persist any rules
    /// the hook added.
    ///
    /// The whole resolution aborts on the first explicit `Denied`,
    /// the hook returning `Abort`, or a hook contract violation. On
    /// error, the policy is consumed and lost; callers wanting to
    /// retain it across a failed resolution must clone beforehand.
    ///
    /// # Errors
    ///
    /// See [`ResolveError`].
    pub fn resolve(
        self,
        policy: UserPolicy,
        hooks: &dyn PolicyHooks,
        options: ResolveOptions,
    ) -> Result<(Resolution, UserPolicy), ResolveError> {
        let (vars_policy, patches_policy) = policy.into_parts();
        let (vars, vars_policy) = resolve_vars(self.vars, vars_policy, hooks)?;
        // Patch sources and policy patterns expand against the
        // resolved vars produced by `resolve_vars`. Explicit `$VAR`
        // references require an explicit `SessionVar` — no env
        // fallback. The tilde prefix (`~/...`) is the one exception:
        // it falls back to the ambient `HOME` if the loadout didn't
        // declare one, so users don't have to write
        // `HOME = { inherit = true }` just to use `~/dotfiles/...`.
        let ambient_home = (self.env)("HOME").ok();
        let (patches, patches_policy) = resolve_patches(
            self.patches,
            patches_policy,
            hooks,
            options,
            &vars,
            ambient_home.as_deref(),
        )?;
        let final_policy = UserPolicy::empty()
            .with_vars(vars_policy)
            .with_patches(patches_policy);
        let resolution = Resolution {
            vars,
            patches,
            packages: self.packages,
            lifecycle_hooks: self.lifecycle_hooks,
        };
        Ok((resolution, final_policy))
    }
}

// =====================================================================
// Per-domain resolution
// =====================================================================

/// Push, drop, or fail on a single [`Decision`].
///
/// Used by Pass 1 (categorizing every item) and by Pass 3's `UseRule`
/// branch (re-checking after the hook mutated the policy). The caller
/// supplies extractors for the `Denied` arm so the helper stays
/// agnostic to whether items are vars or patches. Closures are `Fn` so
/// they're reusable across loop iterations.
fn apply_decision<T>(
    decision: Decision<T>,
    allowed: &mut Vec<T>,
    name_of: impl Fn(&T) -> String,
    source_of: impl Fn(T) -> Source,
) -> Result<(), ResolveError> {
    match decision {
        Decision::Allowed(t) => allowed.push(t),
        Decision::Ignored => {}
        Decision::Denied(t) => {
            let what = name_of(&t);
            return Err(ResolveError::Denied {
                what,
                from: source_of(t),
            });
        }
    }
    Ok(())
}

fn resolve_vars(
    items: Vec<ProvenancedVar>,
    mut policy: VarsPolicy,
    hooks: &dyn PolicyHooks,
) -> Result<(Vec<SessionVar>, VarsPolicy), ResolveError> {
    let name_of = |pv: &ProvenancedVar| pv.var.name().to_owned();
    let source_of = |pv: ProvenancedVar| pv.source;

    // Pass 1: categorize.
    let mut allowed: Vec<ProvenancedVar> = Vec::new();
    let mut unapproved: Vec<ProvenancedVar> = Vec::new();
    for pv in items {
        let name = pv.var.name().to_owned();
        match policy.check(&name, pv) {
            CheckOutcome::Decided(d) => apply_decision(d, &mut allowed, name_of, source_of)?,
            CheckOutcome::NeedsApproval(pv) => unapproved.push(pv),
        }
    }
    if !unapproved.is_empty() {
        // Pass 2: prompt. Hand the hook an owned copy of the policy
        // so it cannot mutate ours directly.
        let view: Vec<Unapproved<'_, str>> = unapproved
            .iter()
            .map(|pv| Unapproved {
                item: pv.var.name(),
                source: &pv.source,
            })
            .collect();
        let decisions = match hooks.on_var_unapproved(policy.clone(), &view) {
            HookResult::Decided {
                decisions,
                updated_policy,
            } => {
                if let Some(new_policy) = updated_policy {
                    policy = new_policy;
                }
                decisions
            }
            HookResult::Abort => return Err(ResolveError::Aborted),
        };
        if decisions.len() != unapproved.len() {
            return Err(ResolveError::HookContract {
                kind: "var-domain hook returned the wrong number of decisions",
                context: format!("expected {}, got {}", unapproved.len(), decisions.len()),
            });
        }
        // Pass 3: apply.
        for (pv, decision) in unapproved.into_iter().zip(decisions) {
            match decision {
                ItemDecision::AllowOnce => allowed.push(pv),
                ItemDecision::DenyOnce => {
                    return Err(ResolveError::Denied {
                        what: name_of(&pv),
                        from: source_of(pv),
                    });
                }
                ItemDecision::UseRule => {
                    let name = pv.var.name().to_owned();
                    match policy.check(&name, pv) {
                        CheckOutcome::Decided(d) => {
                            apply_decision(d, &mut allowed, name_of, source_of)?;
                        }
                        CheckOutcome::NeedsApproval(pv) => {
                            return Err(ResolveError::HookContract {
                                kind: "UseRule returned for a var the policy still cannot decide",
                                context: format!("variable `{}`", pv.var.name()),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok((
        allowed
            .into_iter()
            .map(|pv| SessionVar {
                var: pv.var,
                source: pv.source,
            })
            .collect(),
        policy,
    ))
}

/// Per-file entry derived from a [`Patch`] after its source [`FileSet`]
/// is walked.
///
/// `link_path` is `Some` only when symlink resolution produced a
/// distinct path from `target_path` — i.e. `follow_symlinks: true` was
/// set AND the walker traversed an actual symlink. In every other case
/// the link is implicitly the target, and `link_path` is `None`.
///
/// Both paths are realmed [`HostAbsPath`] — the resolver upholds the
/// absoluteness invariant via the
/// [`ExpandError::NotAbsolute`](crate::expansion::ExpandError::NotAbsolute)
/// gate at expansion time, and `target_path` is also canonical (via
/// [`std::fs::canonicalize`]).
///
/// Policy matching runs against both when both are present — a deny
/// on either wins.
///
/// [`Patch`]: crate::patches::Patch
/// [`FileSet`]: crate::patches::FileSet
struct PatchFile {
    /// `Some` when the file was reached via a symlink that resolved
    /// to a distinct canonical target; `None` when no link is in play
    /// (the common case).
    link_path: Option<HostAbsPath>,
    /// Canonical absolute path the link resolves to. Always the path
    /// used for actual host I/O.
    target_path: HostAbsPath,
    /// Destination for this file, relative to the sandbox user's home
    /// directory. Derived from the user-facing path (link when present,
    /// target otherwise) relative to the patch's walk root, joined
    /// under the patch's `dest`.
    dest: SandboxRelPath,
    /// The original patch's provenance.
    provenance: Source,
}

impl PatchFile {
    /// The path the user "asked for" — the link form when distinct
    /// from the target, otherwise the target itself. Used for
    /// user-facing display (error messages, prompt context) and dest
    /// computation.
    fn user_facing(&self) -> &HostAbsPath {
        self.link_path.as_ref().unwrap_or(&self.target_path)
    }
}

impl Provenanced for PatchFile {
    fn source(&self) -> &Source {
        &self.provenance
    }
}

/// A patch whose source string has been expanded into a concrete
/// [`FileSet`] against the session's resolved vars. Internal handoff
/// type between [`expand_patch_sources`] and [`enumerate_patch_files`].
///
/// [`FileSet`]: crate::patches::FileSet
struct ExpandedProvenancedPatch {
    source: crate::patches::FileSet,
    dest: crate::patches::PatchDest,
    provenance: Source,
}

/// Expand every patch's raw source string against `resolved_vars` and
/// return the parallel list with `FileSet` sources. Fails fast on the
/// first [`ExpandError`](crate::expansion::ExpandError); a partial
/// resolution would let some patches reach the walker with their
/// references intact, which silently matches wrong paths.
fn expand_patch_sources(
    patches: Vec<ProvenancedPatch>,
    resolved_vars: &[SessionVar],
    home_fallback: Option<&str>,
) -> Result<Vec<ExpandedProvenancedPatch>, ResolveError> {
    patches
        .into_iter()
        .map(|pp| {
            let source =
                crate::expansion::expand_source(pp.patch.source(), resolved_vars, home_fallback)?;
            Ok(ExpandedProvenancedPatch {
                source,
                dest: pp.patch.dest().clone(),
                provenance: pp.source,
            })
        })
        .collect()
}

/// Walk each pre-expanded patch's `FileSet` and produce one
/// [`PatchFile`] per matched host file.
///
/// **Path safety:** every yielded file is canonicalized via
/// [`std::fs::canonicalize`] — so when `follow_symlinks` is true the
/// symlink target is known, and dual-path policy checks become
/// possible downstream. The walk itself starts from the un-canonical
/// `walk_root` so the yielded link paths preserve the user's
/// structural intent (matching against the original glob pattern and
/// driving dest computation).
///
/// `..` and `.` components are rejected at expansion time, so they
/// can't appear in the walk root or yielded paths. A non-existent
/// walk root surfaces as a walkdir error on first iteration.
///
/// All errors across every patch are accumulated — a permission-denied
/// subtree under one patch doesn't hide an unwalkable pattern in
/// another. If any error occurred, they surface together as
/// [`ResolveError::PatchWalk`]; otherwise the file list is returned
/// cleanly.
fn enumerate_patch_files(
    items: Vec<ExpandedProvenancedPatch>,
    follow_symlinks: bool,
) -> Result<Vec<PatchFile>, ResolveError> {
    let mut out = Vec::new();
    let mut accumulated_errors = Vec::new();
    for pp in items {
        let Some(walk_root) = pp.source.walk_root() else {
            accumulated_errors.push(crate::patches::Error::NoWalkRoot {
                pattern: pp.source.pattern().to_owned(),
            });
            continue;
        };
        let walk_root_path = walk_root.as_utf8_path().to_path_buf();
        let dest_root = pp.dest.as_sandbox_path().as_utf8_path();
        for entry_result in
            walkdir::WalkDir::new(walk_root_path.as_std_path()).follow_links(follow_symlinks)
        {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(source) => {
                    accumulated_errors.push(crate::patches::Error::WalkFailure {
                        root: walk_root_path.clone(),
                        source,
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let link_path = match Utf8PathBuf::from_path_buf(entry.into_path()) {
                Ok(p) => p,
                Err(p) => {
                    accumulated_errors.push(crate::patches::Error::NonUtf8Path {
                        path_lossy: p.to_string_lossy().into_owned(),
                    });
                    continue;
                }
            };
            if !pp.source.is_match(&link_path) {
                continue;
            }
            // Walker-yielded paths are descended from `walk_root_path`,
            // which is an absolute path because expansion already
            // rejected anything else. `new_unchecked` is sound.
            let walker_path = HostAbsPath::new_unchecked(link_path.clone());
            // When `follow_symlinks` is true, canonicalize each match
            // to obtain the symlink target. Default mode skips this:
            // walkdir filters symlinks-to-files at the `is_file()`
            // check above, so the walker-yielded path *is* the
            // canonical form (or near enough), and canonicalizing
            // would swap in OS-level prefix-symlink forms (e.g.
            // macOS's `/tmp` → `/private/tmp`) that policy patterns
            // don't anticipate.
            let (link_path, target_path) = if follow_symlinks {
                let canonical = match canonicalize_utf8(&link_path) {
                    Ok(p) => p,
                    Err(e) => {
                        accumulated_errors.push(e);
                        continue;
                    }
                };
                let target = HostAbsPath::new_unchecked(canonical);
                // `Some(link)` only if the canonical target actually
                // differs from the walker path. For non-symlink
                // files, target == walker_path and we record None.
                let link = if target.as_utf8_path() == walker_path.as_utf8_path() {
                    None
                } else {
                    Some(walker_path)
                };
                (link, target)
            } else {
                (None, walker_path)
            };
            let user_facing = link_path.as_ref().unwrap_or(&target_path);
            let dest = compute_dest(user_facing.as_utf8_path(), &walk_root_path, dest_root);
            out.push(PatchFile {
                link_path,
                target_path,
                dest,
                provenance: pp.provenance.clone(),
            });
        }
    }
    if accumulated_errors.is_empty() {
        return Ok(out);
    }
    Err(ResolveError::PatchWalk {
        sources: accumulated_errors,
    })
}

/// [`std::fs::canonicalize`] with UTF-8 enforcement.
///
/// Returns [`crate::patches::Error::CanonicalizeFailure`] for any IO
/// error — the path doesn't exist, the process can't traverse the
/// prefix, or (most subtly) the path is a symlink loop. Returns
/// [`crate::patches::Error::NonUtf8CanonicalPath`] if the canonical
/// form contains non-UTF-8 bytes (e.g. a parent directory with a
/// non-UTF-8 name).
fn canonicalize_utf8(path: &Utf8Path) -> Result<Utf8PathBuf, crate::patches::Error> {
    match std::fs::canonicalize(path.as_std_path()) {
        Ok(p) => {
            Utf8PathBuf::from_path_buf(p).map_err(|p| crate::patches::Error::NonUtf8CanonicalPath {
                path_lossy: p.to_string_lossy().into_owned(),
            })
        }
        Err(source) => Err(crate::patches::Error::CanonicalizeFailure {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Compute the destination for a single source file under a patch's
/// `dest`. The result is relative to the sandbox user's home directory,
/// inherited from the patch's [`PatchDest`].
///
/// - **Single-file patches** (`walk_root == source_path`): `dest` is
///   used verbatim.
/// - **Multi-file patches**: the source path's components beneath
///   `walk_root` are appended to `dest`. The strip is path-component
///   aware (camino's `strip_prefix`), so `/etc/xdg` will not match
///   `/etc/xdgfoo/`.
///
/// # Invariants (panic conditions)
///
/// Both panics describe resolver-internal contracts that
/// `enumerate_patch_files` is responsible for upholding. They should
/// be unreachable in normal operation; if one fires, it indicates a
/// bug in this crate.
///
/// 1. `walk_root` must be a path-component prefix of `source_path`.
///    `enumerate_patch_files` walks `walk_root`, so every file it
///    yields is a descendant.
/// 2. `dest_root` is relative (it came from a [`SandboxRelPath`]) and
///    `suffix` is relative (it's the stripped tail), so the join
///    cannot produce an absolute path.
fn compute_dest(
    source_path: &Utf8Path,
    walk_root: &Utf8Path,
    dest_root: &Utf8Path,
) -> SandboxRelPath {
    let root_path = walk_root;
    let joined: Utf8PathBuf = if source_path == root_path {
        dest_root.to_path_buf()
    } else {
        let suffix = source_path.strip_prefix(root_path).unwrap_or_else(|_| {
            panic!(
                "resolver invariant: source path {source_path} is outside walk root {root_path}",
            )
        });
        if dest_root.as_str().is_empty() {
            suffix.to_path_buf()
        } else {
            dest_root.join(suffix)
        }
    };
    SandboxRelPath::try_new(joined)
        .expect("resolver invariant: dest_root and suffix are both relative")
}

fn resolve_patches(
    items: Vec<ProvenancedPatch>,
    mut policy: PatchPolicy,
    hooks: &dyn PolicyHooks,
    options: ResolveOptions,
    resolved_vars: &[SessionVar],
    home_fallback: Option<&str>,
) -> Result<(Vec<SessionPatch>, PatchPolicy), ResolveError> {
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
    let mut expanded = policy.expand_with(resolved_vars, home_fallback)?;

    // Expand every patch source: convert raw strings to `FileSet`s
    // against the already-resolved vars. The resulting list is what
    // the walker actually traverses.
    let expanded_patches = expand_patch_sources(items, resolved_vars, home_fallback)?;
    let files = enumerate_patch_files(expanded_patches, options.follow_symlinks)?;

    // Pass 1: categorize per file. Dual-path check — both the link
    // path (what the walker yielded, if distinct) and the canonical
    // target path must pass policy; a deny on either wins.
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
        // Pass 2: prompt. Hand the hook the *raw* policy so any rules
        // it adds stay in pre-expansion form. Prompt items present
        // the user-facing path (link form when distinct, target
        // otherwise); if a hook needs both forms separately, that's a
        // future API extension.
        let view: Vec<Unapproved<'_, Utf8Path>> = unapproved
            .iter()
            .map(|pf| Unapproved {
                item: pf.user_facing().as_utf8_path(),
                source: &pf.provenance,
            })
            .collect();
        let decisions = match hooks.on_patch_unapproved(policy.clone(), &view) {
            HookResult::Decided {
                decisions,
                updated_policy,
            } => {
                if let Some(new_policy) = updated_policy {
                    policy = new_policy;
                    // Re-expand the new policy against the same vars.
                    // A pattern in the hook's policy that references an
                    // unresolved var becomes a hard `Expansion` error.
                    expanded = policy.expand_with(resolved_vars, home_fallback)?;
                }
                decisions
            }
            HookResult::Abort => return Err(ResolveError::Aborted),
        };
        if decisions.len() != unapproved.len() {
            return Err(ResolveError::HookContract {
                kind: "patch-domain hook returned the wrong number of decisions",
                context: format!("expected {}, got {}", unapproved.len(), decisions.len()),
            });
        }
        // Pass 3: apply.
        for (pf, decision) in unapproved.into_iter().zip(decisions) {
            match decision {
                ItemDecision::AllowOnce => allowed.push(pf),
                ItemDecision::DenyOnce => {
                    return Err(ResolveError::Denied {
                        what: name_of(&pf),
                        from: source_of(pf),
                    });
                }
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
                            return Err(ResolveError::HookContract {
                                kind: "UseRule returned for a patch file the policy still cannot decide",
                                context: format!("source path `{}`", pf.user_facing()),
                            });
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

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patches::PatchDest;
    use crate::vars::{ResolvedVar, VarValue};
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
            path: HostPath::new("/repo"),
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

    /// Default `pv` uses a Project source so allow/deny/prompt logic
    /// actually exercises — user origin would short-circuit via the
    /// bypass.
    fn pv(name: &str) -> ProvenancedVar {
        pv_with(name, project_source())
    }

    type VarsPolicyMutator = Box<dyn Fn(&mut VarsPolicy)>;

    /// Hook driver: enqueue var-domain responses; panic on patch-domain.
    /// `with_mutator` lets a test mutate the *owned copy* of the policy
    /// before the hook's response is consumed; the resulting copy is
    /// what's returned in `updated_policy`.
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
            // If a mutator ran and the response didn't already specify
            // an updated_policy, install the mutated copy.
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
    /// Returns the tempdir guard (caller keeps alive) and the patch.
    fn single_file_patch(name: &str, dest: &str) -> (tempfile::TempDir, Patch) {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
        let file = root.join(name);
        std::fs::write(file.as_std_path(), "x").unwrap();
        let patch = Patch::new(file.as_str(), PatchDest::try_new(dest).unwrap());
        (tmp, patch)
    }

    // =================================================================
    // Vars resolution
    // =================================================================

    mod vars_resolution {
        use super::*;

        #[test]
        fn allow_passes_through_with_source_preserved() {
            let policy = VarsPolicy::empty().try_with_allow(["A_*"]).unwrap();
            let (out, _) = resolve_vars(vec![pv("A_FOO")], policy, &PanicHook).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].var().name(), "A_FOO");
            assert_eq!(out[0].source(), &project_source());
        }

        #[test]
        fn ignore_drops_silently() {
            let policy = VarsPolicy::empty().try_with_ignore(["_*"]).unwrap();
            let (out, _) = resolve_vars(vec![pv("_TMP")], policy, &PanicHook).unwrap();
            assert!(out.is_empty());
        }

        #[test]
        fn deny_errors() {
            let policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
            let err = resolve_vars(vec![pv("AWS_KEY")], policy, &PanicHook).unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        /// User-origin items bypass `allow`/`deny` and never reach the
        /// hook. `PanicHook` ensures that path stays cold.
        #[test]
        fn user_loadout_bypasses_deny_without_prompting() {
            let policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
            let (out, _) =
                resolve_vars(vec![pv_with("AWS_KEY", user_source())], policy, &PanicHook).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].var().name(), "AWS_KEY");
        }

        /// Even user-origin items are still subject to `ignore`.
        #[test]
        fn user_loadout_still_honors_ignore() {
            let policy = VarsPolicy::empty().try_with_ignore(["_*"]).unwrap();
            let (out, _) =
                resolve_vars(vec![pv_with("_TMP", user_source())], policy, &PanicHook).unwrap();
            assert!(out.is_empty());
        }

        /// The bypass is user-only — `Source::Package` items still hit
        /// `deny`.
        #[test]
        fn package_origin_still_denied() {
            let policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
            let pkg_pv = pv_with(
                "AWS_KEY",
                Source::Package {
                    name: "evil-pkg".into(),
                },
            );
            let err = resolve_vars(vec![pkg_pv], policy, &PanicHook).unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        #[test]
        fn hook_allow_once() {
            let policy = VarsPolicy::empty();
            let hook = ScriptedHook::new(vec![HookResult::decided(vec![ItemDecision::AllowOnce])]);
            let (out, _) = resolve_vars(vec![pv("MY_FOO")], policy, &hook).unwrap();
            assert_eq!(out.len(), 1);
        }

        #[test]
        fn hook_deny_once() {
            let policy = VarsPolicy::empty();
            let hook = ScriptedHook::new(vec![HookResult::decided(vec![ItemDecision::DenyOnce])]);
            let err = resolve_vars(vec![pv("MY_FOO")], policy, &hook).unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }));
        }

        #[test]
        fn hook_use_rule_without_mutation_errors_as_hook_contract() {
            let policy = VarsPolicy::empty();
            let hook = ScriptedHook::new(vec![HookResult::decided(vec![ItemDecision::UseRule])]);
            let err = resolve_vars(vec![pv("MY_FOO")], policy, &hook).unwrap_err();
            assert!(
                matches!(err, ResolveError::HookContract { .. }),
                "got: {err:?}"
            );
        }

        #[test]
        fn hook_abort_propagates() {
            let policy = VarsPolicy::empty();
            let hook = ScriptedHook::new(vec![HookResult::Abort]);
            let err = resolve_vars(vec![pv("MY_FOO")], policy, &hook).unwrap_err();
            assert!(matches!(err, ResolveError::Aborted));
        }

        #[test]
        fn hook_decision_count_mismatch_errors() {
            let policy = VarsPolicy::empty();
            let hook = ScriptedHook::new(vec![HookResult::decided(vec![
                ItemDecision::AllowOnce,
                ItemDecision::AllowOnce,
            ])]);
            let err = resolve_vars(vec![pv("MY_FOO")], policy, &hook).unwrap_err();
            assert!(
                matches!(err, ResolveError::HookContract { .. }),
                "got: {err:?}"
            );
        }

        /// Hook returns three different decisions over three items;
        /// mutator adds a rule the middle `UseRule` consults. Catches
        /// zip-ordering regressions in Pass 3.
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
            let (out, _) = resolve_vars(
                vec![pv("FIRST"), pv("MIDDLE_OK"), pv("LAST")],
                policy,
                &hook,
            )
            .unwrap();
            let names: Vec<_> = out.iter().map(|sv| sv.var().name()).collect();
            assert_eq!(names, ["FIRST", "MIDDLE_OK", "LAST"]);
        }
    }

    // =================================================================
    // Patches resolution
    // =================================================================

    mod patches_resolution {
        use super::*;

        /// User origin + empty policy: short-circuits at Pass 1.
        /// `PanicHook` proves no prompt is needed.
        #[test]
        fn user_origin_single_file_short_circuits() {
            let (_tmp, patch) = single_file_patch("hello.txt", "config/hello.txt");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].source(), &user_source());
        }

        /// Project origin + empty policy: must prompt; `PassThroughHook`
        /// approves.
        #[test]
        fn project_origin_goes_through_prompt() {
            let (_tmp, patch) = single_file_patch("conf.toml", "etc/conf.toml");
            let pp = ProvenancedPatch::new(patch, project_source());
            let policy = PatchPolicy::empty();
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PassThroughHook,
                ResolveOptions::default(),
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
            let err = resolve_patches(
                vec![pp],
                policy,
                &PassThroughHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        /// User-origin patches bypass `deny`. `PanicHook` ensures bypass
        /// at Pass 1, not via the prompt.
        #[test]
        fn user_loadout_bypasses_deny() {
            let (_tmp, patch) = single_file_patch("secret.pem", "config/x");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_deny(["/**/*.pem"]);
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
        }

        #[test]
        fn user_loadout_still_honors_ignore() {
            let (_tmp, patch) = single_file_patch("trash.bak", "config/x");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_ignore(["/**/*.bak"]);
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert!(resolved.is_empty());
        }

        /// Build a [`SessionVar`] for tests where the resolver expects
        /// a value to substitute into `$VAR` or `~/` references.
        fn home_var(value: &str) -> SessionVar {
            let resolved =
                ResolvedVar::resolve_with("HOME".into(), VarValue::specified(value), |_| {
                    Err(std::env::VarError::NotPresent)
                })
                .unwrap();
            SessionVar::new(resolved, user_source())
        }

        /// Multi-file glob expands to N `SessionPatch`es with dests
        /// rebuilt from the relative tail.
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
            let (mut resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap();
            resolved.sort();
            let dests: Vec<_> = resolved
                .iter()
                .map(|sp| sp.patch().destination().as_str())
                .collect();
            assert_eq!(dests, ["nvim/a.lua", "nvim/sub/b.lua"]);
        }

        /// Walking a non-existent directory surfaces as
        /// `ResolveError::PatchWalk` (IO-shaped).
        #[test]
        fn walk_failure_surfaces_as_patch_walk() {
            let patch = Patch::new(
                "/definitely/does/not/exist/*",
                PatchDest::try_new("x").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(err, ResolveError::PatchWalk { ref sources } if !sources.is_empty()),
                "got: {err:?}",
            );
        }

        /// A `~/...` source pattern with no `HOME` in the resolved
        /// vars surfaces as `Expansion(UndefinedVar)` — not a silent
        /// empty walk. `PanicHook` proves the error fires before any
        /// hook routing.
        #[test]
        fn tilde_pattern_with_missing_home_var_errors() {
            let patch = Patch::new("~/dotfiles/conf", PatchDest::try_new("conf").unwrap());
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::Expansion(crate::expansion::ExpandError::UndefinedVar { ref name })
                        if name == "HOME"
                ),
                "got: {err:?}",
            );
        }

        /// `~/...` source expansion against a `HOME` session var
        /// successfully walks and finds files.
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
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
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

        /// A `deny = ["~/.ssh/**"]` policy pattern actually denies a
        /// project-origin patch after policy expansion against
        /// the resolved `HOME`.
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

            let err = resolve_patches(
                vec![pp],
                policy,
                &PassThroughHook,
                ResolveOptions::default(),
                &vars,
                None,
            )
            .unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        /// A policy with a `~`-prefixed pattern and no `HOME` in the
        /// resolved-vars set fails up-front with `Expansion`, not a
        /// silent allow.
        #[test]
        fn policy_tilde_pattern_without_home_var_errors() {
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_deny(["~/.ssh/**"]);
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::Expansion(crate::expansion::ExpandError::UndefinedVar { ref name })
                        if name == "HOME"
                ),
                "got: {err:?}",
            );
        }

        /// `~user/...` is not a tilde-prefix expansion candidate, so
        /// it passes through expansion literally — and is then
        /// rejected by the absoluteness check because it doesn't
        /// start with `/`. Surfaces as `ResolveError::Expansion`
        /// carrying `ExpandError::NotAbsolute`.
        #[test]
        fn user_prefixed_tilde_is_rejected_as_relative() {
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().with_deny(["~someuser/.ssh/**"]);
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::Expansion(crate::expansion::ExpandError::NotAbsolute { .. })
                ),
                "got: {err:?}",
            );
        }

        /// The returned policy preserves raw `~/` patterns — round-trip
        /// safe. Expansion happens to an internal copy only.
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

            let (_resolved, policy_out) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &vars,
                None,
            )
            .unwrap();

            assert_eq!(policy_out.allow(), ["~/.config/**"]);
        }

        /// Hook returns an `updated_policy` with a fresh `~/*.pem`
        /// deny rule. The resolver must re-expand against the same
        /// resolved-vars and enforce the rule on `UseRule` re-check.
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

            let err = resolve_patches(
                vec![pp],
                policy,
                &TildeDenyAddingHook,
                ResolveOptions::default(),
                &vars,
                None,
            )
            .unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        /// Hook returns an `updated_policy` that references a var not
        /// in the resolved-vars set. Strict re-expansion: surfaces as
        /// `ResolveError::Expansion`, not silent fall-through.
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
            let err = resolve_patches(
                vec![pp],
                policy,
                &UnknownVarHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::Expansion(crate::expansion::ExpandError::UndefinedVar { ref name })
                        if name == "NOT_RESOLVED"
                ),
                "got: {err:?}",
            );
        }

        // ---- canonicalization + symlink dual-path ----

        /// Create a symlink (Unix-only).
        #[cfg(unix)]
        fn symlink(target: &std::path::Path, link: &std::path::Path) {
            std::os::unix::fs::symlink(target, link).expect("symlink");
        }

        /// A symlinked walk root walks the link's contents (preserving
        /// link-path semantics) and each yielded file's canonical
        /// target is captured. Verifies that follow-symlinks descent
        /// works end-to-end and matches against the link-form pattern.
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
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions {
                    follow_symlinks: true,
                },
                &[],
                None,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
        }

        /// With `follow_symlinks: true`, a symlink file pointing to a
        /// denied location must be rejected. Even though the link's
        /// own path is allowed, the target's path matches deny.
        /// Deny-wins-over-allowed is the security-critical case.
        #[cfg(unix)]
        #[test]
        fn symlink_target_denied_wins_over_link_allowed() {
            let tmp = tempfile::tempdir().unwrap();
            // Canonicalize the tempdir root so the policy patterns
            // below match the form the resolver actually sees. On
            // macOS `tempdir()` returns paths under `/var/folders/...`,
            // which is itself a symlink to `/private/var/folders/...`;
            // with `follow_symlinks: true` the resolver canonicalizes
            // each matched file and that prefix swap would mis-match
            // a policy pattern written against the as-returned form.
            let canonical = std::fs::canonicalize(tmp.path()).unwrap();
            let root = Utf8Path::from_path(&canonical).unwrap().to_path_buf();
            // /tmp/.../allowed_dir/secret -> /tmp/.../denied_dir/leak
            let allowed_dir = root.join("allowed_dir");
            let denied_dir = root.join("denied_dir");
            std::fs::create_dir_all(allowed_dir.as_std_path()).unwrap();
            std::fs::create_dir_all(denied_dir.as_std_path()).unwrap();
            let target_file = denied_dir.join("leak");
            std::fs::write(target_file.as_std_path(), "secret").unwrap();
            let link_file = allowed_dir.join("secret");
            symlink(target_file.as_std_path(), link_file.as_std_path());

            // Patch source covers `allowed_dir/**`. With follow_symlinks
            // the link is followed and yielded as a file.
            let patch = Patch::new(
                format!("{allowed_dir}/**"),
                PatchDest::try_new("etc").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, project_source());
            // Deny matches the canonical target, not the link.
            let policy = PatchPolicy::empty().with_deny([format!("{denied_dir}/**")]);
            let err = resolve_patches(
                vec![pp],
                policy,
                &PassThroughHook,
                ResolveOptions {
                    follow_symlinks: true,
                },
                &[],
                None,
            )
            .unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        /// With `follow_symlinks: true` walking over a *non-*symlinked
        /// file, canonicalization yields the same path the walker
        /// produced — so `PatchFile::link_path` ends up `None` (no
        /// distinct link form to record). Verified by asserting the
        /// file passes a policy whose deny pattern is written in the
        /// *canonical* form: there's no separate link path to clear
        /// the deny against, so it works as a single-path check.
        #[cfg(unix)]
        #[test]
        fn follow_symlinks_on_normal_file_uses_target_only() {
            let tmp = tempfile::tempdir().unwrap();
            // Canonicalize the tempdir root — see the comment on
            // `symlink_target_denied_wins_over_link_allowed` for why
            // macOS makes this necessary.
            let canonical = std::fs::canonicalize(tmp.path()).unwrap();
            let root = Utf8Path::from_path(&canonical).unwrap().to_path_buf();
            // No symlink here — just a plain file. With `follow_symlinks`
            // on, canonicalization runs but yields the same path.
            std::fs::write(root.join("ok.txt").as_std_path(), "x").unwrap();
            let patch = Patch::new(
                format!("{root}/**/*.txt"),
                PatchDest::try_new("etc").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, project_source());
            // Allow that matches the canonical path. If link were
            // erroneously set to Some(walker_path), and walker_path
            // happened to differ from canonical (e.g. via prefix-level
            // OS symlinks), this allow wouldn't cover it. On a plain
            // file with no link, link_path is None and the allow on
            // the target alone is sufficient.
            let policy = PatchPolicy::empty().with_allow([format!("{root}/**")]);
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions {
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
        /// the user-visible prefix (`<link>/...`) mis-match the
        /// canonical target prefix (`<real>/...`) and innocent files
        /// silently fall through to `NeedsApproval`. This test
        /// reconstructs that scenario locally: a symlinked directory
        /// as the walk-root prefix, plus an allow pattern written in
        /// link-prefix terms. With the fix, the file matches policy
        /// `allow` at Pass 1 and `PanicHook` is never invoked. Without
        /// the fix, dual-path mis-matches and resolution routes the
        /// file to the hook — `PanicHook` then panics with a clear
        /// message.
        #[cfg(unix)]
        #[test]
        fn symlinked_prefix_in_default_mode_matches_link_form_policy() {
            let tmp = tempfile::tempdir().unwrap();
            let tmp_root = Utf8Path::from_path(tmp.path()).unwrap();
            let real = tmp_root.join("real_dir");
            std::fs::create_dir_all(real.as_std_path()).unwrap();
            std::fs::write(real.join("conf.toml").as_std_path(), "x").unwrap();
            // `link_dir` is a symlink to `real_dir`. Patch source +
            // policy allow are both written against `link_dir`.
            let link = tmp_root.join("link_dir");
            symlink(real.as_std_path(), link.as_std_path());

            let patch = Patch::new(
                format!("{link}/**/*.toml"),
                PatchDest::try_new("etc").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, project_source());

            // Allow pattern written in link-prefix terms. In default
            // mode (no follow_symlinks), canonicalization must not
            // swap in `real_dir`; otherwise this allow won't match.
            let policy = PatchPolicy::empty().with_allow([format!("{link}/**")]);
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &[],
                None,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
        }
    }

    // =================================================================
    // PathDecision combinator
    // =================================================================

    mod path_decision_combinator {
        use super::*;
        use PathDecision::{Allowed, Denied, Ignored, NeedsApproval};

        #[test]
        fn deny_beats_everything() {
            assert_eq!(Denied.combine(Allowed), Denied);
            assert_eq!(Allowed.combine(Denied), Denied);
            assert_eq!(Denied.combine(Ignored), Denied);
            assert_eq!(Ignored.combine(Denied), Denied);
            assert_eq!(Denied.combine(NeedsApproval), Denied);
            assert_eq!(NeedsApproval.combine(Denied), Denied);
            assert_eq!(Denied.combine(Denied), Denied);
        }

        #[test]
        fn ignore_beats_approval_and_allow_but_not_deny() {
            assert_eq!(Ignored.combine(Allowed), Ignored);
            assert_eq!(Allowed.combine(Ignored), Ignored);
            assert_eq!(Ignored.combine(NeedsApproval), Ignored);
            assert_eq!(NeedsApproval.combine(Ignored), Ignored);
            assert_eq!(Ignored.combine(Ignored), Ignored);
        }

        #[test]
        fn approval_beats_allow() {
            assert_eq!(NeedsApproval.combine(Allowed), NeedsApproval);
            assert_eq!(Allowed.combine(NeedsApproval), NeedsApproval);
            assert_eq!(NeedsApproval.combine(NeedsApproval), NeedsApproval);
        }

        #[test]
        fn both_allowed_is_allowed() {
            assert_eq!(Allowed.combine(Allowed), Allowed);
        }
    }

    // =================================================================
    // compute_dest invariants
    // =================================================================

    mod compute_dest_invariants {
        use super::*;

        #[test]
        fn multi_file_appends_relative_path() {
            let source = Utf8Path::new("/etc/xdg/sub/file.conf");
            let walk_root = Utf8Path::new("/etc/xdg");
            let dest = compute_dest(source, walk_root, Utf8Path::new("config"));
            assert_eq!(dest.as_str(), "config/sub/file.conf");
        }

        #[test]
        fn single_file_uses_dest_verbatim() {
            let source = Utf8Path::new("/home/u/file.conf");
            let walk_root = Utf8Path::new("/home/u/file.conf");
            let dest = compute_dest(source, walk_root, Utf8Path::new("etc/foo.conf"));
            assert_eq!(dest.as_str(), "etc/foo.conf");
        }

        /// Regression for component-boundary strip — `/etc/xdg` must
        /// not match `/etc/xdgfoo/bar`. Resolver invariant; we panic
        /// rather than produce a garbage dest.
        #[test]
        #[should_panic(expected = "outside walk root")]
        fn panics_on_source_outside_walk_root() {
            let source = Utf8Path::new("/etc/xdgfoo/bar");
            let walk_root = Utf8Path::new("/etc/xdg");
            let _ = compute_dest(source, walk_root, Utf8Path::new("dst"));
        }
    }

    // =================================================================
    // Composer public API
    // =================================================================

    mod composer_api {
        use super::*;

        #[test]
        fn empty_composer_yields_empty_resolution() {
            let composer = Composer::new();
            let (resolution, _) = composer
                .resolve(UserPolicy::empty(), &PanicHook, ResolveOptions::default())
                .unwrap();
            assert!(resolution.vars().is_empty());
            assert!(resolution.patches().is_empty());
        }

        #[test]
        fn minimal_session_round_trips() {
            let (_tmp, patch) = single_file_patch("conf.toml", "etc/conf.toml");
            let loadout = FakeLoadout {
                source: user_source(),
                var_names: vec!["EDITOR"],
                patches: vec![patch],
            };
            let mut composer = Composer::new();
            composer.add(loadout).unwrap();
            let (resolution, _policy_out) = composer
                .resolve(UserPolicy::empty(), &PanicHook, ResolveOptions::default())
                .unwrap();
            assert_eq!(resolution.vars().len(), 1);
            assert_eq!(resolution.patches().len(), 1);
        }

        /// When a hook returns `updated_policy: Some(new)`, the
        /// returned `UserPolicy` carries that mutation. Project-origin
        /// item forces a prompt; hook returns an updated `VarsPolicy`
        /// with an `allow = ["MUT_*"]` rule.
        #[test]
        fn returned_policy_carries_hook_mutation() {
            struct MutatingHook;
            impl PolicyHooks for MutatingHook {
                fn on_var_unapproved(
                    &self,
                    policy: VarsPolicy,
                    items: &[Unapproved<'_, str>],
                ) -> HookResult<VarsPolicy> {
                    let updated = policy.try_with_allow(["MUT_*"]).unwrap();
                    HookResult::decided_with_policy(
                        vec![ItemDecision::UseRule; items.len()],
                        updated,
                    )
                }
                fn on_patch_unapproved(
                    &self,
                    _: PatchPolicy,
                    items: &[Unapproved<'_, camino::Utf8Path>],
                ) -> HookResult<PatchPolicy> {
                    HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
                }
            }

            let mut composer = Composer::new();
            composer
                .add(FakeLoadout::vars(project_source(), vec!["MUT_FOO"]))
                .unwrap();

            let (_resolution, policy_out) = composer
                .resolve(
                    UserPolicy::empty(),
                    &MutatingHook,
                    ResolveOptions::default(),
                )
                .unwrap();
            assert!(
                policy_out.vars().allow().is_match("MUT_FOO"),
                "expected MUT_* allow rule on returned policy, got: {:?}",
                policy_out.vars().allow(),
            );
        }

        /// Test scaffold: a tiny Composable that contributes a fixed
        /// set of vars and patches sharing one source.
        struct FakeLoadout {
            source: Source,
            var_names: Vec<&'static str>,
            patches: Vec<Patch>,
        }

        impl FakeLoadout {
            fn vars(source: Source, var_names: Vec<&'static str>) -> Self {
                Self {
                    source,
                    var_names,
                    patches: Vec::new(),
                }
            }
        }

        impl Provenanced for FakeLoadout {
            fn source(&self) -> &Source {
                &self.source
            }
        }

        impl Composable for FakeLoadout {
            fn contribute(self, _env: EnvLookup<'_>) -> Result<Contribution, Error> {
                let mut c = Contribution::new();
                for name in self.var_names {
                    c.push_var(pv_with(name, self.source.clone()));
                }
                for patch in self.patches {
                    c.push_patch(ProvenancedPatch::new(patch, self.source.clone()));
                }
                Ok(c)
            }
        }

        /// `Composer::add` drives the canonical contributor path.
        #[test]
        fn add_drains_a_composable() {
            let loadout = FakeLoadout::vars(user_source(), vec!["EDITOR", "LANG"]);
            let mut composer = Composer::new();
            composer.add(loadout).unwrap();
            let (resolution, _) = composer
                .resolve(UserPolicy::empty(), &PanicHook, ResolveOptions::default())
                .unwrap();
            assert_eq!(resolution.vars().len(), 2);
        }

        /// `Composer::add_all` runs a sequence of contributors. Multiple
        /// sources accumulate independently.
        #[test]
        fn add_all_runs_a_sequence_of_contributors() {
            let loadouts = vec![
                FakeLoadout::vars(user_source(), vec!["EDITOR"]),
                FakeLoadout::vars(project_source(), vec!["LANG", "TZ"]),
            ];
            let mut composer = Composer::new();
            composer.add_all(loadouts).unwrap();
            let (resolution, _) = composer
                .resolve(
                    UserPolicy::empty(),
                    &PassThroughHook,
                    ResolveOptions::default(),
                )
                .unwrap();
            assert_eq!(resolution.vars().len(), 3);
            let by_source: Vec<_> = resolution.vars().iter().map(SessionVar::source).collect();
            assert!(by_source.contains(&&user_source()));
            assert!(by_source.contains(&&project_source()));
        }

        /// `Composer::add` propagates a contributor's error verbatim.
        #[test]
        fn add_propagates_contributor_error() {
            struct FailingLoadout;
            impl Provenanced for FailingLoadout {
                fn source(&self) -> &Source {
                    static S: std::sync::OnceLock<Source> = std::sync::OnceLock::new();
                    S.get_or_init(|| Source::UserLoadout {
                        name: "failing".into(),
                    })
                }
            }
            impl Composable for FailingLoadout {
                fn contribute(self, _env: EnvLookup<'_>) -> Result<Contribution, Error> {
                    // Trigger a real construction-time error from one of
                    // the underlying domains.
                    crate::patches::FileSet::try_new("[invalid").map_err(Error::from)?;
                    unreachable!()
                }
            }
            let mut composer = Composer::new();
            let err = composer.add(FailingLoadout).unwrap_err();
            assert!(matches!(err, Error::Patch { .. }), "got: {err:?}");
        }

        /// Packages and lifecycle hooks contributed via a Composable
        /// pass through to the final Resolution unchanged.
        #[test]
        fn packages_and_hooks_pass_through() {
            use crate::lifecyclehook::{HookScript, LifecycleHook};

            struct LoadoutWithExtras;
            impl Composable for LoadoutWithExtras {
                fn contribute(self, _env: EnvLookup<'_>) -> Result<Contribution, Error> {
                    let hook = LifecycleHook::builder()
                        .with_on_activate(HookScript::inline("echo go"))
                        .build()?;
                    Ok(Contribution::new()
                        .with_package(ProvenancedPackage::new("helix", user_source()))
                        .with_package(ProvenancedPackage::new("zellij", user_source()))
                        .with_hook(ProvenancedHook::new(hook, user_source())))
                }
            }

            let mut composer = Composer::new();
            composer.add(LoadoutWithExtras).unwrap();
            let (resolution, _) = composer
                .resolve(UserPolicy::empty(), &PanicHook, ResolveOptions::default())
                .unwrap();
            assert_eq!(resolution.packages().len(), 2);
            assert_eq!(resolution.packages()[0].package(), "helix");
            assert_eq!(resolution.lifecycle_hooks().len(), 1);
            assert_eq!(resolution.lifecycle_hooks()[0].source(), &user_source());
        }

        /// `Composer::with_env` lets tests pin env behavior without
        /// touching the process environment. The provided closure
        /// resolves `LANG` when a contributor's var is `inherit = true`.
        #[test]
        fn with_env_overrides_lookup_for_inheriting_vars() {
            use crate::loadout::{Loadout, LoadoutName};
            use crate::vars::{StrictVarName, VarValue};

            let loadout = Loadout::new(LoadoutName::try_new("dev").unwrap())
                .with_var(StrictVarName::try_new("LANG").unwrap(), VarValue::Inherit);

            let mut composer = Composer::new().with_env(Box::new(|name| {
                if name == "LANG" {
                    Ok("en_US.UTF-8".into())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            }));
            composer.add(loadout).unwrap();
            let (resolution, _) = composer
                .resolve(UserPolicy::empty(), &PanicHook, ResolveOptions::default())
                .unwrap();
            assert_eq!(resolution.vars().len(), 1);
            assert_eq!(resolution.vars()[0].var().name(), "LANG");
            assert_eq!(resolution.vars()[0].var().value(), "en_US.UTF-8");
        }

        /// End-to-end test that `Loadout` is now a real `Composable`.
        /// Push a loadout with vars, patches, packages, and a hook;
        /// verify all four kinds reach the Resolution.
        #[test]
        fn loadout_contributes_all_four_kinds() {
            use crate::lifecyclehook::{HookScript, LifecycleHook};
            use crate::loadout::{Loadout, LoadoutName};
            use crate::vars::{StrictVarName, VarValue};

            let (_tmp, patch) = single_file_patch("conf.toml", "etc/conf.toml");

            let hook = LifecycleHook::builder()
                .with_on_activate(HookScript::inline("echo hi"))
                .build()
                .unwrap();

            let loadout = Loadout::new(LoadoutName::try_new("dev").unwrap())
                .with_var(
                    StrictVarName::try_new("EDITOR").unwrap(),
                    VarValue::specified("hx"),
                )
                .with_package("helix")
                .with_patch(patch)
                .with_lifecycle_hook(hook);

            let mut composer = Composer::new();
            composer.add(loadout).unwrap();
            let (resolution, _) = composer
                .resolve(UserPolicy::empty(), &PanicHook, ResolveOptions::default())
                .unwrap();
            assert_eq!(resolution.vars().len(), 1);
            assert_eq!(resolution.patches().len(), 1);
            assert_eq!(resolution.packages().len(), 1);
            assert_eq!(resolution.lifecycle_hooks().len(), 1);

            // All four share the same UserLoadout source.
            let expected = Source::UserLoadout { name: "dev".into() };
            assert_eq!(resolution.vars()[0].source(), &expected);
            assert_eq!(resolution.patches()[0].source(), &expected);
            assert_eq!(resolution.packages()[0].source(), &expected);
            assert_eq!(resolution.lifecycle_hooks()[0].source(), &expected);
        }
    }

    // =================================================================
    // FileSet::resolve direct (unit, not via resolver)
    // =================================================================

    #[test]
    fn fileset_resolve_errors_when_pattern_has_no_walk_root() {
        let fs = crate::patches::FileSet::try_new("**/*.pem").unwrap();
        let (paths, errors) = fs.resolve(false);
        assert!(paths.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(
            matches!(&errors[0], crate::patches::Error::NoWalkRoot { .. }),
            "got: {:?}",
            errors[0],
        );
    }

    // =================================================================
    // Display snapshots — guard the user-facing error strings.
    // =================================================================

    mod display_snapshots {
        use super::*;

        #[test]
        fn resolve_error_denied() {
            let err = ResolveError::Denied {
                what: "AWS_KEY".into(),
                from: user_source(),
            };
            assert_eq!(
                err.to_string(),
                "policy denied `AWS_KEY` (from user loadout `test`)",
            );
        }

        #[test]
        fn resolve_error_aborted() {
            assert_eq!(
                ResolveError::Aborted.to_string(),
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
}
