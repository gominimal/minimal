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

/// A lookup function for resolving the host user's home directory.
///
/// Threaded through [`Composer::resolve`] so the patch resolver can
/// expand leading `~` in source patterns. Returns `None` when no home
/// is available (e.g. `$HOME` unset and no `passwd` entry); the
/// resolver surfaces that as [`ResolveError::HomeUnresolved`] when a
/// pattern actually requires it.
///
/// Invoked at most twice per resolution: once at the top of
/// [`Composer::resolve`] if any `~`-prefixed pattern exists, and once
/// more if a hook returns an `updated_policy` introducing new
/// `~`-prefixed rules. A `~`-free policy in a `HOME`-less environment
/// never triggers the lookup.
///
/// Production callers should pass [`dirs::home_dir`]; tests can pin a
/// synthetic closure via [`Composer::with_home`].
pub type HomeLookup<'a> = &'a dyn Fn() -> Option<std::path::PathBuf>;

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
    /// A patch source has an unwalkable configuration — typically a
    /// pattern with no literal path prefix. The user must fix their
    /// loadout/project config; retrying without changes will not help.
    ///
    /// Surfaced separately from [`PatchWalk`](Self::PatchWalk) because
    /// configuration errors and transient IO failures have different
    /// audiences (the loadout author vs. the operator).
    #[error("patch source configuration is invalid ({} error(s)):{}", sources.len(), DisplayJoin(sources))]
    PatchConfig { sources: Vec<crate::patches::Error> },
    /// One or more patch source filesystem walks failed with IO-level
    /// errors (permission denied, non-UTF-8 paths, etc.). All errors
    /// surfaced by every `FileSet::resolve` invocation are accumulated
    /// — none are discarded.
    #[error("patch resolution failed ({} error(s)):{}", sources.len(), DisplayJoin(sources))]
    PatchWalk { sources: Vec<crate::patches::Error> },
    /// At least one patch source or policy pattern starts with `~`,
    /// but resolving the host home directory failed.
    ///
    /// Both failure modes (no home available; non-UTF-8 home path)
    /// live under one variant because the home lookup happens once at
    /// the start of resolution — not per pattern — so the error has
    /// no pattern context to surface. Match on the inner
    /// [`HomeResolutionFailure`] to distinguish causes.
    #[error("a `~`-prefixed pattern requires home expansion, but {0}")]
    HomeUnresolved(#[from] HomeResolutionFailure),
}

/// Why home-directory resolution failed during patch resolution.
///
/// All variants describe operator/environment problems, not
/// loadout-config problems: the loadout author can't fix any of them.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HomeResolutionFailure {
    /// No home directory was found (e.g. `$HOME` unset and no
    /// `passwd` entry).
    #[error("no home directory was found")]
    Unavailable,
    /// The home directory's path is not valid UTF-8.
    #[error("home directory is not valid UTF-8: `{lossy}`")]
    NotUtf8 { lossy: String },
    /// The home directory's path is not absolute. Home is expected to
    /// be absolute by POSIX convention; a relative result indicates a
    /// misbehaving `HomeLookup`.
    #[error("home directory is not absolute: `{0}`")]
    NotAbsolute(Utf8PathBuf),
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
/// Boxed home-lookup closure stored in [`Composer`]. `Send + Sync`
/// for the reasons documented on [`StoredEnv`].
type StoredHome = Box<dyn Fn() -> Option<std::path::PathBuf> + Send + Sync>;

pub struct Composer {
    vars: Vec<ProvenancedVar>,
    patches: Vec<ProvenancedPatch>,
    packages: Vec<ProvenancedPackage>,
    lifecycle_hooks: Vec<ProvenancedHook>,
    env: StoredEnv,
    home: StoredHome,
}

impl fmt::Debug for Composer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Composer")
            .field("vars", &self.vars)
            .field("patches", &self.patches)
            .field("packages", &self.packages)
            .field("lifecycle_hooks", &self.lifecycle_hooks)
            .field("env", &"<closure>")
            .field("home", &"<closure>")
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
    /// Construct an empty composer with default lookups:
    /// [`std::env::var`] for env, [`dirs::home_dir`] for home.
    /// Suitable for production code.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vars: Vec::new(),
            patches: Vec::new(),
            packages: Vec::new(),
            lifecycle_hooks: Vec::new(),
            env: Box::new(|name| std::env::var(name)),
            home: Box::new(dirs::home_dir),
        }
    }

    /// Replace the env lookup. Useful for tests that want to pin env
    /// behavior without touching the process environment.
    #[must_use]
    pub fn with_env(mut self, env: StoredEnv) -> Self {
        self.env = env;
        self
    }

    /// Replace the home-directory lookup. Useful for tests that want
    /// to pin a synthetic `$HOME` without touching `dirs::home_dir`.
    #[must_use]
    pub fn with_home(mut self, home: StoredHome) -> Self {
        self.home = home;
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
        let (patches, patches_policy) =
            resolve_patches(self.patches, patches_policy, hooks, options, &*self.home)?;
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
struct PatchFile {
    /// Absolute host path to the file.
    source_path: Utf8PathBuf,
    /// Destination for this file, relative to the sandbox user's home
    /// directory.
    dest: SandboxRelPath,
    /// The original patch's provenance.
    provenance: Source,
}

impl Provenanced for PatchFile {
    fn source(&self) -> &Source {
        &self.provenance
    }
}

/// Enumerate every file each `Patch` source glob expands to.
///
/// All errors are accumulated. After the walk, errors are partitioned
/// by kind: configuration errors (e.g. [`patches::Error::NoWalkRoot`])
/// take priority over transient IO walk errors, so the user fixes the
/// config first. If only IO errors occurred, those surface as
/// [`ResolveError::PatchWalk`].
///
/// [`patches::Error::NoWalkRoot`]: crate::patches::Error::NoWalkRoot
fn enumerate_patch_files(
    items: Vec<ProvenancedPatch>,
    follow_symlinks: bool,
    home: Option<&HostAbsPath>,
) -> Result<Vec<PatchFile>, ResolveError> {
    let mut out = Vec::new();
    let mut accumulated_errors = Vec::new();
    for pp in items {
        // Expand a leading `~` in the FileSet pattern before walking.
        // `expand_home` returns a fresh FileSet (via re-parse) or a
        // borrow of the existing one — `Cow` derefs to `&FileSet`
        // either way. Gate on `home` so `expand_home` only ever
        // receives a concrete `&HostAbsPath`.
        let expanded_source = match home {
            Some(h) => expand_home(pp.patch.source(), h)?,
            None => std::borrow::Cow::Borrowed(pp.patch.source()),
        };

        let Some(walk_root) = expanded_source.walk_root() else {
            // FileSet::resolve will also report NoWalkRoot; we still
            // call it for symmetry of error accumulation.
            let (_files, errors) = expanded_source.resolve(follow_symlinks);
            accumulated_errors.extend(errors);
            continue;
        };
        let (files, errors) = expanded_source.resolve(follow_symlinks);
        accumulated_errors.extend(errors);
        let dest_root = pp.patch.dest().as_sandbox_path().as_utf8_path();
        for file in files {
            let source_path = file.as_utf8_path().to_path_buf();
            let dest = compute_dest(&source_path, &walk_root, dest_root);
            out.push(PatchFile {
                source_path,
                dest,
                provenance: pp.source.clone(),
            });
        }
    }
    if accumulated_errors.is_empty() {
        return Ok(out);
    }
    let (config, walk): (Vec<_>, Vec<_>) = accumulated_errors
        .into_iter()
        .partition(is_patch_config_error);
    if !config.is_empty() {
        return Err(ResolveError::PatchConfig { sources: config });
    }
    Err(ResolveError::PatchWalk { sources: walk })
}

/// Expand a leading `~` or `~/` prefix in a
/// [`FileSet`](crate::patches::FileSet) pattern against the resolved
/// home directory.
///
/// Only the literal `~` (alone) or `~/<rest>` prefix is expanded —
/// `~user` is intentionally not supported, and a mid-path `~` is
/// preserved as a literal `~` character.
///
/// Returns the original `FileSet` borrowed (zero alloc) when the
/// pattern doesn't begin with `~`. Returns a fresh `FileSet` (one
/// re-parse) when expansion happens.
///
/// The home argument is unconditional: callers are expected to gate
/// the call on whether any tilde pattern is in scope, so by the time
/// this function runs we always know a usable home is available.
fn expand_home<'a>(
    fs: &'a crate::patches::FileSet,
    home: &HostAbsPath,
) -> Result<std::borrow::Cow<'a, crate::patches::FileSet>, ResolveError> {
    let pattern = fs.pattern();
    let suffix = if pattern == "~" {
        ""
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        rest
    } else {
        return Ok(std::borrow::Cow::Borrowed(fs));
    };
    // Trim trailing slashes once so both arms below produce
    // symmetric output (no `//` in the `~/x` case, no trailing `/`
    // in the bare `~` case).
    let home = home.as_str().trim_end_matches('/');
    let expanded = if suffix.is_empty() {
        home.to_owned()
    } else {
        format!("{home}/{suffix}")
    };
    let new_fs = crate::patches::FileSet::try_new(expanded)
        .map_err(|e| ResolveError::PatchConfig { sources: vec![e] })?;
    Ok(std::borrow::Cow::Owned(new_fs))
}

/// Resolve the host home directory via the supplied [`HomeLookup`],
/// normalizing to UTF-8 and enforcing absoluteness. Surfaces all
/// three failure modes as [`ResolveError::HomeUnresolved`].
fn resolve_home(lookup: HomeLookup<'_>) -> Result<HostAbsPath, ResolveError> {
    let Some(path) = lookup() else {
        return Err(ResolveError::HomeUnresolved(
            HomeResolutionFailure::Unavailable,
        ));
    };
    let utf8 = Utf8PathBuf::from_path_buf(path).map_err(|p| {
        ResolveError::HomeUnresolved(HomeResolutionFailure::NotUtf8 {
            lossy: p.to_string_lossy().into_owned(),
        })
    })?;
    HostAbsPath::try_new(utf8).map_err(|e| match e {
        paths::Error::NotAbsolute(p) => {
            ResolveError::HomeUnresolved(HomeResolutionFailure::NotAbsolute(p))
        }
        other => panic!("HostAbsPath::try_new returned unexpected variant: {other:?}"),
    })
}

/// `true` for errors that mean "the user's loadout/project config is
/// wrong" rather than "the host filesystem misbehaved."
fn is_patch_config_error(e: &crate::patches::Error) -> bool {
    matches!(e, crate::patches::Error::NoWalkRoot { .. })
}

/// Produce a [`PatchPolicy`] whose `allow` / `deny` / `ignore` patterns
/// have had leading `~` expanded against `home`.
///
/// The resolver keeps two policies in flight: the raw form (handed to
/// the hook, returned to the caller — preserves round-trip) and this
/// expanded form (used for the actual `check` calls — patterns
/// actually match the on-disk paths the walker yields).
///
/// Per-list short-circuit: any list with no `~`-prefixed pattern is
/// reused verbatim. Lists that need expansion are rebuilt. A policy
/// with `~` only in `deny` (say) leaves `allow` and `ignore`
/// untouched.
///
/// Takes `home` unconditionally; callers that don't have a home
/// resolved should not call this function at all (the policy is
/// already in its final form). [`expand_policy_home_opt`] is the
/// convenience wrapper for the common case.
fn expand_policy_home(
    raw: &crate::patches::PatchPolicy,
    home: &HostAbsPath,
) -> Result<crate::patches::PatchPolicy, ResolveError> {
    fn map_sets(
        sets: &[crate::patches::FileSet],
        home: &HostAbsPath,
    ) -> Result<Vec<crate::patches::FileSet>, ResolveError> {
        if !any_tilde(sets) {
            // No expansion needed; clone the list as-is.
            return Ok(sets.to_vec());
        }
        sets.iter()
            .map(|fs| Ok(expand_home(fs, home)?.into_owned()))
            .collect()
    }
    Ok(crate::patches::PatchPolicy::empty()
        .with_allow(map_sets(raw.allow(), home)?)
        .with_deny(map_sets(raw.deny(), home)?)
        .with_ignore(map_sets(raw.ignore(), home)?))
}

/// `Option<&HostAbsPath>` wrapper around [`expand_policy_home`]: when
/// `home` is `None` (no `~` patterns anywhere), the raw policy is
/// already its own expanded form, so just clone it.
fn expand_policy_home_opt(
    raw: &crate::patches::PatchPolicy,
    home: Option<&HostAbsPath>,
) -> Result<crate::patches::PatchPolicy, ResolveError> {
    match home {
        Some(h) => expand_policy_home(raw, h),
        None => Ok(raw.clone()),
    }
}

/// `true` if any [`FileSet`](crate::patches::FileSet) in `sets`
/// starts with `~`.
fn any_tilde(sets: &[crate::patches::FileSet]) -> bool {
    sets.iter().any(|fs| fs.pattern().starts_with('~'))
}

/// `true` if any pattern in the policy starts with `~`. Used at the
/// top of [`resolve_patches`] to decide whether to invoke the home
/// lookup.
fn policy_has_tilde_pattern(p: &crate::patches::PatchPolicy) -> bool {
    any_tilde(p.allow()) || any_tilde(p.deny()) || any_tilde(p.ignore())
}

/// `true` if any patch source pattern starts with `~`. Used at the
/// top of [`resolve_patches`] alongside [`policy_has_tilde_pattern`]
/// to decide whether to invoke the home lookup.
fn patches_have_tilde_pattern(items: &[ProvenancedPatch]) -> bool {
    items
        .iter()
        .any(|pp| pp.patch.source().pattern().starts_with('~'))
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
    walk_root: &HostPath,
    dest_root: &Utf8Path,
) -> SandboxRelPath {
    let root_path = walk_root.as_utf8_path();
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
    home_lookup: HomeLookup<'_>,
) -> Result<(Vec<SessionPatch>, PatchPolicy), ResolveError> {
    let name_of = |pf: &PatchFile| pf.source_path.as_str().to_owned();
    let source_of = |pf: PatchFile| pf.provenance;

    // Resolve the host home directory up-front if (and only if) any
    // `~`-prefixed pattern is in scope. Cached as `Option<HostAbsPath>`
    // and reused across passes; refreshed only if the hook later
    // introduces a `~`-prefixed rule into the policy and we hadn't
    // resolved before. A `~`-free resolution never invokes the
    // lookup.
    let mut home: Option<HostAbsPath> =
        if patches_have_tilde_pattern(&items) || policy_has_tilde_pattern(&policy) {
            Some(resolve_home(home_lookup)?)
        } else {
            None
        };

    let files = enumerate_patch_files(items, options.follow_symlinks, home.as_ref())?;

    // Two policies in flight:
    //   - `policy` (raw): handed to the hook, returned to the caller —
    //     patterns retain their `~` form so the policy round-trips.
    //   - `expanded`: home-expanded copy used for the actual `check`
    //     calls — patterns actually match the absolute paths the
    //     walker yields. Re-derived whenever the hook updates the
    //     policy.
    let mut expanded = expand_policy_home_opt(&policy, home.as_ref())?;

    // Pass 1: categorize per file.
    let mut allowed: Vec<PatchFile> = Vec::new();
    let mut unapproved: Vec<PatchFile> = Vec::new();
    for pf in files {
        let path = pf.source_path.clone();
        match expanded.check(&path, pf) {
            CheckOutcome::Decided(d) => apply_decision(d, &mut allowed, name_of, source_of)?,
            CheckOutcome::NeedsApproval(pf) => unapproved.push(pf),
        }
    }
    if !unapproved.is_empty() {
        // Pass 2: prompt. Hand the hook the *raw* policy so any rules
        // it adds stay in `~/`-relative form.
        let view: Vec<Unapproved<'_, Utf8Path>> = unapproved
            .iter()
            .map(|pf| Unapproved {
                item: pf.source_path.as_path(),
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
                    // If the hook introduced `~`-prefixed rules and we
                    // hadn't already resolved home, resolve it now.
                    if home.is_none() && policy_has_tilde_pattern(&policy) {
                        home = Some(resolve_home(home_lookup)?);
                    }
                    expanded = expand_policy_home_opt(&policy, home.as_ref())?;
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
                    let path = pf.source_path.clone();
                    match expanded.check(&path, pf) {
                        CheckOutcome::Decided(d) => {
                            apply_decision(d, &mut allowed, name_of, source_of)?;
                        }
                        CheckOutcome::NeedsApproval(pf) => {
                            return Err(ResolveError::HookContract {
                                kind: "UseRule returned for a patch file the policy still cannot decide",
                                context: format!("source path `{}`", pf.source_path),
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
                patch: ResolvedPatch::new(HostAbsPath::new_unchecked(pf.source_path), pf.dest),
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
    use crate::patches::{FileSet, PatchDest};
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

    /// Default `HomeLookup` for tests: returns `None`. Tests that
    /// actually need home expansion (or whose paths happen to start
    /// with `~`) should override this.
    fn no_home() -> impl Fn() -> Option<std::path::PathBuf> {
        || None
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
        let patch = Patch::new(
            FileSet::try_new(file.as_str()).unwrap(),
            PatchDest::try_new(dest).unwrap(),
        );
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
                &no_home(),
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
                &no_home(),
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].source(), &project_source());
        }

        #[test]
        fn deny_via_policy_errors() {
            let (_tmp, patch) = single_file_patch("secret.pem", "config/x");
            let pp = ProvenancedPatch::new(patch, project_source());
            let policy = PatchPolicy::empty().try_with_deny(["**/*.pem"]).unwrap();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PassThroughHook,
                ResolveOptions::default(),
                &no_home(),
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
            let policy = PatchPolicy::empty().try_with_deny(["**/*.pem"]).unwrap();
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
        }

        #[test]
        fn user_loadout_still_honors_ignore() {
            let (_tmp, patch) = single_file_patch("trash.bak", "config/x");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().try_with_ignore(["**/*.bak"]).unwrap();
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
            )
            .unwrap();
            assert!(resolved.is_empty());
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
            let patch = Patch::new(
                FileSet::try_new(pattern).unwrap(),
                PatchDest::try_new("nvim").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let (mut resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
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
        /// `ResolveError::PatchWalk` (IO-shaped), not `PatchConfig`.
        #[test]
        fn walk_failure_surfaces_as_patch_walk() {
            let patch = Patch::new(
                FileSet::try_new("/definitely/does/not/exist/*").unwrap(),
                PatchDest::try_new("x").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
            )
            .unwrap_err();
            assert!(
                matches!(err, ResolveError::PatchWalk { ref sources } if !sources.is_empty()),
                "got: {err:?}",
            );
        }

        /// A pattern with no walk root surfaces as `PatchConfig`,
        /// distinct from `PatchWalk`.
        #[test]
        fn no_walk_root_surfaces_as_patch_config() {
            let patch = Patch::new(
                FileSet::try_new("**/*.pem").unwrap(),
                PatchDest::try_new("x").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
            )
            .unwrap_err();
            assert!(
                matches!(err, ResolveError::PatchConfig { ref sources } if !sources.is_empty()),
                "got: {err:?}",
            );
        }

        /// A `~/...` source pattern with a missing home directory
        /// surfaces as `HomeUnresolved` — not a silent empty walk.
        ///
        /// Uses `&PanicHook` because the error must fire from the
        /// up-front home-resolution step in `resolve_patches`, before
        /// any patch is even walked or routed to the hook. If a future
        /// refactor reorders resolution to walk/check before resolving
        /// home, this test fails fast at the panic hook with a clear
        /// "hook should not have been invoked" message rather than a
        /// confusing wrong-error assertion.
        #[test]
        fn tilde_pattern_with_missing_home_errors() {
            let patch = Patch::new(
                FileSet::try_new("~/dotfiles/conf").unwrap(),
                PatchDest::try_new("conf").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::HomeUnresolved(HomeResolutionFailure::Unavailable),
                ),
                "got: {err:?}",
            );
        }

        /// `~/...` source expansion against a stubbed home directory
        /// successfully walks and finds files.
        #[test]
        fn tilde_pattern_expands_with_home_lookup() {
            let tmp = tempfile::tempdir().unwrap();
            let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
            // Layout under the stubbed home:
            //   <home>/dotfiles/conf
            std::fs::create_dir_all(root.join("dotfiles").as_std_path()).unwrap();
            std::fs::write(root.join("dotfiles/conf").as_std_path(), "x").unwrap();

            let patch = Patch::new(
                FileSet::try_new("~/dotfiles/conf").unwrap(),
                PatchDest::try_new("conf").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let home_path = root.clone().into_std_path_buf();
            let home = move || Some(home_path.clone());
            let (resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &home,
            )
            .unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(
                resolved[0].patch().host_path().as_str(),
                root.join("dotfiles/conf").as_str(),
            );
        }

        /// A `deny = ["~/.ssh/**"]` policy pattern actually denies a
        /// project-origin patch whose source matches the expanded
        /// path. Without policy expansion the deny would silently
        /// match nothing (literal `~` vs. absolute `/home/...`).
        #[test]
        fn policy_tilde_pattern_actually_denies() {
            let tmp = tempfile::tempdir().unwrap();
            let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
            std::fs::create_dir_all(root.join(".ssh").as_std_path()).unwrap();
            std::fs::write(root.join(".ssh/id_rsa").as_std_path(), "secret").unwrap();

            // Project-origin so the deny rule applies (user origin
            // bypasses).
            let patch = Patch::new(
                FileSet::try_new(root.join(".ssh/id_rsa").as_str()).unwrap(),
                PatchDest::try_new("id_rsa").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, project_source());

            let policy = PatchPolicy::empty().try_with_deny(["~/.ssh/**"]).unwrap();
            let home_path = root.clone().into_std_path_buf();
            let home = move || Some(home_path.clone());

            let err = resolve_patches(
                vec![pp],
                policy,
                &PassThroughHook,
                ResolveOptions::default(),
                &home,
            )
            .unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
        }

        /// A home lookup returning a non-UTF-8 path surfaces as
        /// `HomeUnresolved::NotUtf8` — distinct from the "no home
        /// available" case.
        #[cfg(unix)]
        #[test]
        fn non_utf8_home_surfaces_as_not_utf8() {
            use std::os::unix::ffi::OsStringExt;

            let patch = Patch::new(
                FileSet::try_new("~/conf").unwrap(),
                PatchDest::try_new("conf").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            // 0xFF 0xFE is invalid UTF-8.
            let bad_home =
                std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xFF, 0xFE]));
            let home = move || Some(bad_home.clone());
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &home,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::HomeUnresolved(HomeResolutionFailure::NotUtf8 { .. }),
                ),
                "got: {err:?}",
            );
        }

        /// A home lookup returning a relative path surfaces as
        /// `HomeResolutionFailure::NotAbsolute` — home is supposed to be
        /// absolute by POSIX convention, and a relative result means a
        /// broken lookup, not a config error.
        #[test]
        fn relative_home_surfaces_as_not_absolute() {
            let patch = Patch::new(
                FileSet::try_new("~/conf").unwrap(),
                PatchDest::try_new("conf").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty();
            let home = || Some(std::path::PathBuf::from("relative/home"));
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &home,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::HomeUnresolved(HomeResolutionFailure::NotAbsolute(_)),
                ),
                "got: {err:?}",
            );
        }

        /// A policy with a `~`-prefixed pattern but no home lookup
        /// surfaces as `HomeUnresolved` — not silently allowed.
        #[test]
        fn policy_tilde_pattern_without_home_errors() {
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, user_source());
            let policy = PatchPolicy::empty().try_with_deny(["~/.ssh/**"]).unwrap();
            let err = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &no_home(),
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::HomeUnresolved(HomeResolutionFailure::Unavailable),
                ),
                "got: {err:?}",
            );
        }

        /// The returned policy preserves raw `~` patterns — round-trip
        /// safe. Expansion is internal-only.
        #[test]
        fn returned_policy_preserves_raw_tilde_patterns() {
            let tmp = tempfile::tempdir().unwrap();
            let root = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
            let file = root.join("hello.txt");
            std::fs::write(file.as_std_path(), "x").unwrap();

            let patch = Patch::new(
                FileSet::try_new(file.as_str()).unwrap(),
                PatchDest::try_new("hello.txt").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, user_source());

            let policy = PatchPolicy::empty()
                .try_with_allow(["~/.config/**"])
                .unwrap();
            let home_path = root.clone().into_std_path_buf();
            let home = move || Some(home_path.clone());

            let (_resolved, policy_out) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &home,
            )
            .unwrap();

            // Returned policy still says `~/.config/**`, not the
            // expanded form.
            let allow_patterns: Vec<&str> = policy_out
                .allow()
                .iter()
                .map(crate::patches::FileSet::pattern)
                .collect();
            assert_eq!(allow_patterns, ["~/.config/**"]);
        }

        /// Policies with no `~` patterns must not invoke the home
        /// lookup. Pinned by a panicking lookup that fails the test
        /// if it's called. This is the documented fast-path guarantee
        /// for `HOME`-less environments.
        #[test]
        fn no_tilde_policy_does_not_invoke_home_lookup() {
            let (_tmp, patch) = single_file_patch("conf.toml", "conf");
            let pp = ProvenancedPatch::new(patch, user_source());
            // No `~` anywhere — neither the patch source pattern
            // (absolute tempdir) nor the policy pattern.
            let policy = PatchPolicy::empty()
                .try_with_deny(["/etc/forbidden/**"])
                .unwrap();
            let panic_home = || -> Option<std::path::PathBuf> {
                panic!("home lookup must not be invoked when no `~` patterns are present");
            };
            let (_resolved, _) = resolve_patches(
                vec![pp],
                policy,
                &PanicHook,
                ResolveOptions::default(),
                &panic_home,
            )
            .unwrap();
        }

        /// A hook that returns an `updated_policy` containing a new
        /// `~`-prefixed deny rule must have that rule enforced in
        /// Pass 3 — exercising the `expanded = expand_policy_home(...)`
        /// re-derivation after the hook update.
        #[test]
        fn hook_added_tilde_rule_is_enforced_after_reexpansion() {
            /// Hook that returns `UseRule` for every item and installs
            /// a new `~/*.pem` deny rule in `updated_policy`.
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
                    // Hand back the policy with an added `~/*.pem`
                    // deny rule. The resolver must re-expand before
                    // re-checking on UseRule, or the literal `~`
                    // pattern won't match the absolute source path.
                    let updated = policy.try_with_deny(["~/*.pem"]).unwrap();
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

            // Project-origin so allow/deny applies.
            let patch = Patch::new(
                FileSet::try_new(file.as_str()).unwrap(),
                PatchDest::try_new("secret.pem").unwrap(),
            );
            let pp = ProvenancedPatch::new(patch, project_source());

            let policy = PatchPolicy::empty();
            let home_path = root.clone().into_std_path_buf();
            let home = move || Some(home_path.clone());

            let err = resolve_patches(
                vec![pp],
                policy,
                &TildeDenyAddingHook,
                ResolveOptions::default(),
                &home,
            )
            .unwrap_err();
            assert!(matches!(err, ResolveError::Denied { .. }), "got: {err:?}");
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
            let walk_root = HostPath::new("/etc/xdg");
            let dest = compute_dest(source, &walk_root, Utf8Path::new("config"));
            assert_eq!(dest.as_str(), "config/sub/file.conf");
        }

        #[test]
        fn single_file_uses_dest_verbatim() {
            let source = Utf8Path::new("/home/u/file.conf");
            let walk_root = HostPath::new("/home/u/file.conf");
            let dest = compute_dest(source, &walk_root, Utf8Path::new("etc/foo.conf"));
            assert_eq!(dest.as_str(), "etc/foo.conf");
        }

        /// Regression for component-boundary strip — `/etc/xdg` must
        /// not match `/etc/xdgfoo/bar`. Resolver invariant; we panic
        /// rather than produce a garbage dest.
        #[test]
        #[should_panic(expected = "outside walk root")]
        fn panics_on_source_outside_walk_root() {
            let source = Utf8Path::new("/etc/xdgfoo/bar");
            let walk_root = HostPath::new("/etc/xdg");
            let _ = compute_dest(source, &walk_root, Utf8Path::new("dst"));
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
                    FileSet::try_new("[invalid").map_err(Error::from)?;
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
            use crate::patches::{FileSet, PatchDest};
            use crate::vars::{StrictVarName, VarValue};

            let (_tmp, patch) = single_file_patch("conf.toml", "etc/conf.toml");
            let _ = FileSet::try_new("ignored").unwrap();
            let _ = PatchDest::try_new("ignored").unwrap();

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
        let fs = FileSet::try_new("**/*.pem").unwrap();
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
