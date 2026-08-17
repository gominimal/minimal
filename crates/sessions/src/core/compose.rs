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
use std::collections::BTreeMap;

use crate::core::decision::{CheckOutcome, Decision, ItemDecision};
use crate::core::enumerate::{ExpandedProvenancedPatch, PatchFile, enumerate_patch_files};
use crate::core::hooks::{HookResult, PolicyHooks, Unapproved};
use crate::core::policy::{PatchesPolicy, UserPolicy, VarsPolicy};
use crate::core::primitives::{ResolvedPatch, ResolvedVar, VarError};
use crate::core::source::{
    Provenanced, ProvenancedHook, ProvenancedPackage, ProvenancedPatch, ProvenancedVar, Source,
};
use crate::wire::policy::{WirePatchVerdict, WireVarVerdict};
use crate::wire::primitives::{
    PendingId, WirePendingHook, WirePendingPatch, WirePendingVar, WireSessionPatch, WireSessionVar,
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
    /// A loadout with this name was already added to the composer.
    /// Loadout names must be unique within a composer instance so
    /// per-loadout settings (like `follow_symlinks`) can be attributed
    /// unambiguously; a duplicate would silently overwrite an earlier
    /// setting on the map keyed by name.
    #[error("loadout name `{name}` was already added to this composer")]
    DuplicateLoadout { name: String },
}

/// Conflicts surfaced when two contributions disagree on a value.
///
/// A `Conflict` is *always* fatal today: composition cannot proceed
/// when contributors disagree on what a single var should resolve to
/// or where a single patch should come from. The escape hatch is the
/// user's policy ignore list, which (when it matches) drops the
/// offending items during the gate; conflict detection runs
/// *post-gate* on the survivors, so ignored items never reach the
/// comparison.
///
/// Packages and lifecycle hooks have no conflict variants: packages
/// dedupe (set semantics, no value to disagree on) and hooks
/// concatenate (both run, in declaration order).
#[non_exhaustive]
#[derive(Debug)]
pub enum Conflict {
    /// Two or more contributors set the same variable name to
    /// different resolved values.
    VarValueMismatch {
        /// The variable name in question.
        name: String,
        /// Every contributor under this name, paired with the value
        /// they wanted. Always at least two entries; same-value
        /// duplicates are included so the user sees the full
        /// picture, even though they're not what caused the conflict.
        disagreeing_values: Vec<(Source, String)>,
    },
    /// Two or more contributors set the same patch destination to
    /// different sources.
    PatchSourceMismatch {
        /// The destination (sandbox-relative) that contributors
        /// disagreed on.
        dest: paths::SandboxRelPath,
        /// Every contributor under this destination, paired with the
        /// source they declared.
        ///
        /// The `String` is the contributor's declared source: the
        /// raw glob pattern pre-gate (which may still contain `~`
        /// or `$VAR`), or the resolved absolute `host_path`
        /// post-gate. Either way it identifies the input file the
        /// contributor wanted copied.
        disagreeing_sources: Vec<(Source, String)>,
    },
    /// Two patches want to occupy the same tree node from opposite
    /// sides: one contributor's destination is a component-boundary
    /// prefix of another's, so one wants to place a file where the
    /// other expects a directory (or vice versa). Distinct
    /// destinations, so `PatchSourceMismatch` doesn't fire — but
    /// `materialize_patches_into_home` can't create both at Finalize
    /// time (whichever `fs::copy` runs second fails). Caught here so
    /// the operator gets a Compose-time error naming both
    /// contributors instead of a mid-Finalize `NotADirectory` /
    /// `IsADirectory` fault that leaves the session stuck in
    /// `Materializing`.
    PatchDestPrefixCollision {
        /// The shorter destination — the one that would land as a
        /// file directly under `<home>`.
        shorter: paths::SandboxRelPath,
        /// The longer destination, whose parent-chain includes
        /// `shorter` as a directory.
        longer: paths::SandboxRelPath,
        /// The provenance of both contributors.
        ///
        /// Boxed to keep [`Conflict`] — and the two error enums that
        /// embed it, [`Error`] and [`ComposeError`] — under the
        /// `result_large_err` size threshold; this array is by far the
        /// largest payload across every conflict variant.
        contributors: Box<[(Source, paths::SandboxRelPath); 2]>,
    },
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarValueMismatch {
                name,
                disagreeing_values,
            } => {
                write!(f, "variable `{name}` set to conflicting values:")?;
                for (source, value) in disagreeing_values {
                    write!(f, "\n  - {value:?} (from {source})")?;
                }
                // No "set it in your loadout to override" hint:
                // merge has no override semantics — adding another
                // loadout value just adds another disagreeing
                // contributor. Dropping all of them via the ignore
                // list is the only working escape today.
                write!(
                    f,
                    "\nhint: add `{name}` to your policy's ignore list \
                     to drop all of these contributors"
                )
            }
            Self::PatchSourceMismatch {
                dest,
                disagreeing_sources,
            } => {
                write!(f, "patch destination `{dest}` has conflicting sources:")?;
                for (source, src) in disagreeing_sources {
                    write!(f, "\n  - {src:?} (from {source})")?;
                }
                // PatchesPolicy matches against *source* paths, not
                // destinations — the hint must steer the user to a
                // pattern that matches the sources shown above, not
                // the destination.
                write!(
                    f,
                    "\nhint: add a pattern matching the conflicting source path(s) \
                     above to your patch policy's ignore list to drop both, \
                     or remove one of the contributors"
                )
            }
            Self::PatchDestPrefixCollision {
                shorter,
                longer,
                contributors,
            } => {
                write!(
                    f,
                    "patch destinations `{shorter}` and `{longer}` collide: \
                     one wants a file where the other expects a directory"
                )?;
                for (source, dest) in contributors.iter() {
                    write!(f, "\n  - `{dest}` (from {source})")?;
                }
                write!(
                    f,
                    "\nhint: pick destinations that don't nest — e.g. move the \
                     file target under a distinct name, or add a pattern \
                     matching one contributor's source to your patch policy's \
                     ignore list to drop it"
                )
            }
        }
    }
}

impl std::error::Error for Conflict {}

// =====================================================================
// Merge-time conflict detection helpers
// =====================================================================
//
// These three small fns are the *only* place per-domain merge rules
// live. Both [`compose_contribution`] (post-gate, per-side) and
// [`Composition::extend_from_wire`] (post-gate cross-process) call
// them on already-gated items. [`Contribution::merge`] does not
// invoke them — running the checks pre-gate would fire before the
// user's `ignore` policy could drop offending contributors. The
// closure-driven extractors let one body serve every item type that
// impls [`Provenanced`] — `ProvenancedVar` / `SessionVar` for vars,
// `ProvenancedPatch` / `SessionPatch` for patches.
//
// O(n²) worst case, but allocates only on the conflict path: the
// hot path is "no conflicts" and walks without building any
// intermediate map. For the small batches typical here (≪100 items),
// quadratic is cheaper than a `HashMap` allocation.

/// Scan `items` for two entries that share a var name but disagree
/// on the resolved value. The first such name found short-circuits
/// the scan and emits a [`Conflict::VarValueMismatch`] listing every
/// contribution under that name — including any agreeing duplicates,
/// so the message shows the full picture.
///
/// Returns `Ok(())` when every name has at most one distinct value
/// (duplicate same-value entries are not conflicts).
///
/// Taking an `IntoIterator` (rather than `&[T]`) lets callers feed
/// a chained iterator over two separate sources without first
/// allocating the union — important for atomic merges where the
/// helper runs *before* either side has been mutated.
fn check_var_mismatches<'a, T: Provenanced + 'a>(
    items: impl IntoIterator<Item = &'a T>,
    name: impl Fn(&T) -> &str,
    value: impl Fn(&T) -> &str,
) -> Result<(), Conflict> {
    group_by_key(items, &name)
        .into_iter()
        .find_map(|(n, group)| disagreement(&group, &value).then_some((n, group)))
        .map(|(n, group)| Conflict::VarValueMismatch {
            name: n.to_owned(),
            disagreeing_values: collect_contributions(group, &value),
        })
        .map_or(Ok(()), Err)
}

/// Patch counterpart to [`check_var_mismatches`]. `dest` is the
/// conflict key; `pattern` is the source-side representation that
/// disagreement is checked against — the raw source pattern pre-gate,
/// the resolved host path post-gate. Either way it stringifies into
/// the [`Conflict::PatchSourceMismatch`] message.
fn check_patch_mismatches<'a, T: Provenanced + 'a>(
    items: impl IntoIterator<Item = &'a T>,
    dest: impl Fn(&T) -> &paths::SandboxRelPath,
    pattern: impl Fn(&T) -> &str,
) -> Result<(), Conflict> {
    group_by_key(items, &dest)
        .into_iter()
        .find_map(|(d, group)| disagreement(&group, &pattern).then_some((d, group)))
        .map(|(d, group)| Conflict::PatchSourceMismatch {
            dest: d.clone(),
            disagreeing_sources: collect_contributions(group, &pattern),
        })
        .map_or(Ok(()), Err)
}

/// Reject two patches whose destinations are prefixes of one another
/// on a path-component boundary — `foo` vs `foo/bar` — since
/// `materialize_patches_into_home` can't create the shorter as a
/// file *and* the longer as `<shorter>/<tail>`. Caught here so the
/// operator sees a compose-time conflict listing both contributors,
/// rather than a mid-`FinalizeSession` `NotADirectory`/`IsADirectory`
/// I/O error that leaves the session stuck in `Materializing`.
///
/// O(n²) worst-case, matching the existing `check_patch_mismatches`
/// shape — the batches this runs against are small (a few dozen at
/// most in practice).
fn check_patch_prefix_collisions<'a, T: Provenanced + 'a>(
    items: impl IntoIterator<Item = &'a T> + Clone,
    dest: impl Fn(&T) -> &paths::SandboxRelPath,
) -> Result<(), Conflict> {
    let all: Vec<&'a T> = items.into_iter().collect();
    for (i, a) in all.iter().enumerate() {
        let a_dest = dest(a);
        for b in &all[i + 1..] {
            let b_dest = dest(b);
            if a_dest == b_dest {
                // Same-destination collisions are the
                // `PatchSourceMismatch` case: same source is a dup
                // (fine), different source is that other conflict
                // (fires from `check_patch_mismatches`, not here).
                continue;
            }
            let (shorter, longer, shorter_src, longer_src) =
                if is_component_prefix(a_dest.as_utf8_path(), b_dest.as_utf8_path()) {
                    (a_dest, b_dest, a.source(), b.source())
                } else if is_component_prefix(b_dest.as_utf8_path(), a_dest.as_utf8_path()) {
                    (b_dest, a_dest, b.source(), a.source())
                } else {
                    continue;
                };
            return Err(Conflict::PatchDestPrefixCollision {
                shorter: shorter.clone(),
                longer: longer.clone(),
                contributors: Box::new([
                    (shorter_src.clone(), shorter.clone()),
                    (longer_src.clone(), longer.clone()),
                ]),
            });
        }
    }
    Ok(())
}

/// True iff `shorter` is a component-boundary prefix of `longer`
/// (both relative, equal-length is not a prefix — that would be
/// same-destination, covered by `check_patch_mismatches`). Component
/// boundary so `foo` doesn't wrongly match `foobar` (only `foo/bar`).
fn is_component_prefix(shorter: &camino::Utf8Path, longer: &camino::Utf8Path) -> bool {
    let mut s = shorter.components();
    let mut l = longer.components();
    loop {
        match (s.next(), l.next()) {
            // Matched component: keep comparing the rest.
            (Some(a), Some(b)) if a == b => {}
            // `shorter` has an unmatched component (differs here, or is
            // the longer path), or both ran out at equal length — either
            // way `shorter` is not a *proper* component prefix.
            (Some(_), _) | (None, None) => return false,
            // `shorter` ran out while `longer` has more: proper prefix.
            (None, Some(_)) => return true,
        }
    }
}

/// Bucket `items` by `key`, preserving the order in which keys are
/// first encountered. `O(n × distinct-keys)` — fine for the small
/// batches typical here, and avoids the determinism / dependency
/// cost of a `HashMap`.
fn group_by_key<'a, T: 'a, K: PartialEq>(
    items: impl IntoIterator<Item = &'a T>,
    key: impl Fn(&'a T) -> K,
) -> Vec<(K, Vec<&'a T>)> {
    items.into_iter().fold(Vec::new(), |mut acc, item| {
        let k = key(item);
        match acc.iter_mut().find(|(g, _)| *g == k) {
            Some((_, bucket)) => bucket.push(item),
            None => acc.push((k, vec![item])),
        }
        acc
    })
}

/// True when the items in `group` aren't unanimous on what
/// `extract` returns. Compares every item against the first; bails
/// on the first mismatch. An empty group is vacuously unanimous,
/// so this avoids any precondition on `group_by_key`'s output shape.
fn disagreement<T>(group: &[&T], extract: impl Fn(&T) -> &str) -> bool {
    let mut it = group.iter();
    let Some(first) = it.next().map(|x| extract(x)) else {
        return false;
    };
    it.any(|x| extract(x) != first)
}

/// Render every item in `group` as a `(Source, owned-value)` pair
/// for embedding in a `Conflict`'s `contributions` field.
fn collect_contributions<T: Provenanced>(
    group: Vec<&T>,
    extract: impl Fn(&T) -> &str,
) -> Vec<(Source, String)> {
    group
        .into_iter()
        .map(|x| (x.source().clone(), extract(x).to_owned()))
        .collect()
}

/// Stable in-place dedupe by string key — first occurrence wins,
/// later duplicates are dropped. Used for packages, whose set
/// semantics mean two contributors asking for the same package is
/// not a conflict (there's no value to disagree on).
///
/// Not used for vars or patches: same-key same-value duplicates are
/// harmless and kept (matches the prior "pure aggregation" behavior
/// on the no-disagreement path).
fn dedupe_by_name<T>(items: &mut Vec<T>, name: impl Fn(&T) -> &str) {
    // PERF: `seen` is `Vec<String>` (one allocation per unique key)
    // rather than `Vec<&str>` borrowing from `items`. The borrow-tied
    // shape fights `retain`'s `FnMut` requirements — its closure can't
    // hold a borrow of `items` while `retain` itself owns one. The
    // owned approach is the simplest version that compiles; for the
    // small package sets we dedupe over (typically ≤ ~20), the
    // allocation cost is irrelevant.
    let mut seen: Vec<String> = Vec::new();
    items.retain(|item| {
        let n = name(item);
        if seen.iter().any(|s| s == n) {
            false
        } else {
            seen.push(n.to_owned());
            true
        }
    });
}

/// A single source's contribution to a session, materialized as a
/// concrete value rather than streamed into a composer.
///
/// Returned by [`Composable::contribute`]. A composer accumulates
/// these into one bucket via [`Self::merge`] before the gate runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

    /// Overwrite the `follow_symlinks` override on every currently
    /// accumulated patch. Used by
    /// [`Loadout::contribute`](crate::core::loadout::Loadout::contribute)
    /// to stamp the loadout's per-source override after
    /// `contribute_primitives` produced patches with the default
    /// `None`.
    pub fn set_follow_symlinks_on_patches(&mut self, follow: Option<bool>) {
        for p in std::mem::take(&mut self.patches) {
            let (patch, source, _) = p.into_parts();
            self.patches
                .push(ProvenancedPatch::new(patch, source).with_follow_symlinks(follow));
        }
    }

    /// Merge `other` into `self`: concatenate vars/patches/hooks and
    /// dedupe packages. Cross-contributor conflicts are detected
    /// post-gate in [`compose_contribution`], not here.
    ///
    /// # Errors
    ///
    /// Infallible today; `Result` shape kept for a future
    /// interactive resolution hook.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Result shape reserved for future interactive resolution"
    )]
    pub(crate) fn merge(&mut self, other: Contribution) -> Result<(), Conflict> {
        self.vars.extend(other.vars);
        self.patches.extend(other.patches);
        self.packages.extend(other.packages);
        dedupe_by_name(&mut self.packages, ProvenancedPackage::package);
        self.lifecycle_hooks.extend(other.lifecycle_hooks);
        Ok(())
    }

    /// Drop the items a *package* supplied that we refuse to compose:
    /// every patch tagged [`Source::Package`], and every
    /// [`Source::Package`] var that carries user data (an env-inherited
    /// value — [`ResolvedVar::carries_user_data`]).
    ///
    /// A package var with a static (non-user) value, a package's request
    /// for a package (the `packages` list), and every item from a
    /// non-package source are all left untouched. Because vars and
    /// patches are never deduped across sources (each contributor keeps
    /// its own entry — see [`Self::merge`]), dropping the package's own
    /// entry here still leaves any project- or loadout-supplied entry for
    /// the same var name / patch destination intact: an item requested by
    /// a package *and* something else still composes in, via that other
    /// source.
    ///
    /// [`Source::Package`]: crate::core::source::Source::Package
    /// [`ResolvedVar::carries_user_data`]: crate::core::primitives::ResolvedVar::carries_user_data
    pub(crate) fn drop_package_supplied_patches_and_user_data_vars(&mut self) {
        use crate::core::source::{Provenanced, Source};
        self.patches
            .retain(|p| !matches!(p.source(), Source::Package { .. }));
        self.vars.retain(|v| {
            !(matches!(v.source(), Source::Package { .. }) && v.var().carries_user_data())
        });
    }

    /// True when no items have been contributed across any domain.
    /// Used by daemon-side composers to take the empty-contribution
    /// fast path (no pending items to ship back to the client).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
            && self.patches.is_empty()
            && self.packages.is_empty()
            && self.lifecycle_hooks.is_empty()
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

/// Env lookup for the *daemon-side* composer, which must never resolve
/// an inherited var against the daemon's own process environment — the
/// daemon's launch shell is not the user's shell. Every lookup reports
/// the name as present-but-empty: an `Inherit` var resolves without
/// erroring, its placeholder value is discarded, and
/// [`contribution_to_pending`] ships the preserved spec so the client
/// re-resolves against the *user's* env. (`Specified` vars never call
/// the lookup, so their literals are untouched.)
#[must_use]
pub fn deferring_env() -> StoredEnv {
    Box::new(|_name| Ok(String::new()))
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

/// Build a [`Contribution`] from a loadout-shaped primitive set
/// (packages, strict vars, lenient vars, patches, lifecycle hooks)
/// against a single [`Source`], resolving each var against `env`.
///
/// Shared by [`crate::core::loadout::Loadout`]'s and every project /
/// package composable's `contribute` — the only per-source
/// difference is the [`Source`] tag stamped on every produced item,
/// so lifting the loop bodies into one helper prevents the impls
/// from drifting when a new primitive lands.
///
/// Positional args over a named struct because wrapping five fields
/// in a `Primitives`-shaped struct at every callsite (only to
/// immediately destructure inside the fn) is pure ceremony given
/// the shape isn't otherwise reused. If a sixth primitive lands,
/// this signature grows and every caller breaks compile-time —
/// the intended way to spot missed updates.
///
/// # Errors
///
/// See [`Composable::contribute`] — the same
/// [`ResolvedVar::resolve_with`](crate::core::primitives::ResolvedVar::resolve_with)
/// failure modes propagate.
pub fn contribute_primitives(
    source: &crate::core::source::Source,
    packages: Vec<String>,
    vars: std::collections::BTreeMap<
        crate::core::primitives::StrictVarName,
        crate::core::primitives::VarValue,
    >,
    vars_lenient: Vec<crate::core::primitives::LenientVarEntry>,
    patches: crate::core::primitives::Patches,
    lifecycle_hooks: Vec<crate::core::lifecyclehook::LifecycleHook>,
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<Contribution, Error> {
    use crate::core::primitives::ResolvedVar;
    use crate::core::source::{
        ProvenancedHook, ProvenancedPackage, ProvenancedPatch, ProvenancedVar,
    };

    let mut c = Contribution::new();
    for (name, value) in vars {
        let resolved = ResolvedVar::resolve_with(name.into_inner(), value, env)?;
        c.push_var(ProvenancedVar::new(resolved, source.clone()));
    }
    for entry in vars_lenient {
        let (name, value) = entry.into_parts();
        let resolved = ResolvedVar::resolve_with(name.into_inner(), value, env)?;
        c.push_var(ProvenancedVar::new(resolved, source.clone()));
    }
    for patch in patches {
        c.push_patch(ProvenancedPatch::new(patch, source.clone()));
    }
    for pkg in packages {
        c.push_package(ProvenancedPackage::new(pkg, source.clone()));
    }
    for hook in lifecycle_hooks {
        c.push_hook(ProvenancedHook::new(hook, source.clone()));
    }
    Ok(c)
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
    #[error("patch enumeration produced {} error{}:{}", sources.len(), if sources.len() == 1 { "" } else { "s" }, DisplayJoin(sources))]
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
    /// Two contributors disagreed on a var value or patch source.
    /// Surfaces from the post-gate checks in
    /// [`compose_contribution`] (each side's own composition) and
    /// from the cross-process merge in
    /// [`Composition::extend_from_wire`].
    /// [`Contribution::merge`] is pure aggregation and never
    /// produces this variant.
    #[error("contribution merge conflict: {source}")]
    Conflict {
        #[from]
        #[source]
        source: Conflict,
    },
}

/// Which policy domain a hook contract violation refers to. Keeps
/// the `HookContract` message constructors exhaustively dispatched
/// instead of stringly-typed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HookDomain {
    Var,
    Patch,
    Hook,
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
            HookDomain::Hook => {
                "UseRule returned for a project whose hooks the policy still cannot decide"
            }
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
            HookDomain::Hook => "lifecycle-hook-domain hook returned the wrong number of decisions",
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
    /// Direct construction. Crate-internal so external callers can
    /// only obtain a `SessionVar` via the gate or from a
    /// [`WireSessionVar`] — both post-gate by construction.
    #[must_use]
    pub(crate) fn new(var: ResolvedVar, source: Source) -> Self {
        Self(ProvenancedVar::new(var, source))
    }

    /// Lift a gated [`ProvenancedVar`] into a `SessionVar`.
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
    /// Direct construction. Crate-internal so external callers can
    /// only obtain a `SessionPatch` via the gate or from a
    /// [`WireSessionPatch`] — both post-gate by construction.
    #[must_use]
    pub(crate) fn new(patch: ResolvedPatch, source: Source) -> Self {
        Self { patch, source }
    }

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
        // Resolve the daemon-shipped spec against the *user's* env
        // (`env` is the client's `std::env::var`). For an inherited
        // var the daemon shipped `Inherit`/`InheritWithDefault` — never
        // its own value — so this is the single, authoritative
        // resolution, and `resolved.carries_user_data()` correctly
        // reflects whether the value came from the user's environment.
        // `Specified` specs (hardcoded project literals) resolve
        // verbatim with `carries_user_data = false`, as before.
        let resolved = ResolvedVar::resolve_with(wire.name, wire.spec.into(), env).map_err(
            |err| match err {
                VarError::ResolutionFailure { name, source } => {
                    ComposeError::VarResolution { name, source }
                }
                // `resolve_with` only documents `ResolutionFailure` for
                // resolution input, but `VarError` is `#[non_exhaustive]`
                // — fall back to a recoverable error instead of panicking
                // if a new variant ever leaks through.
                other => ComposeError::InvalidWireItem {
                    what: "pending var resolution",
                    context: format!("{other}"),
                },
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
        WireVarVerdict::Approved {
            id: self.id,
            value: resolved.into(),
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
    /// target path and the client-computed per-file destination
    /// back to the daemon. The daemon reuses `destination` verbatim
    /// so a dir mapping's file fan-out lands at distinct sandbox
    /// paths instead of collapsing onto the pending patch's base
    /// dest.
    #[must_use]
    pub(crate) fn into_approved_verdict(self) -> WirePatchVerdict {
        WirePatchVerdict::Approved {
            id: self.id,
            host_path: self.file.target_path,
            destination: self.file.dest,
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

/// Orientation facts for the attached shell's first-prompt banner,
/// carried on the composition as first-class control-plane data — never
/// through the user var lane, so user vars and user policy cannot
/// collide with it. Collected by the client's
/// [`UserComposer`](crate::client::composer::UserComposer) (the only
/// party that knows which loadouts were selected) and read by the
/// session launcher, which seeds the banner env (`MINIMAL_LOADOUTS`)
/// from it in the baseline layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Orientation {
    /// Human-readable display list of the active loadouts (comma-joined
    /// names, `default (built-in)` for the zero-config fallback, `none`
    /// with `--no-loadouts`). Empty means "unknown" — a peer that
    /// predates the field — and seeds nothing.
    pub loadouts_display: String,
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
    /// First-prompt orientation facts; see [`Orientation`]. Client-set:
    /// the daemon-side passthrough never populates it, and
    /// [`Self::extend_from_wire`] installs the client's value.
    orientation: Orientation,
}

impl Composition {
    /// The first-prompt orientation facts the client contributed.
    #[must_use]
    pub fn orientation(&self) -> &Orientation {
        &self.orientation
    }

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
    /// with its source, in **setup order**: the project's hooks first,
    /// then each loadout's in the order the loadouts were selected.
    ///
    /// This is the order the setup transitions (`on_activate`,
    /// `on_attach`) run in, and it is a contract, not an accident of
    /// assembly: the daemon builds its own contribution first and
    /// appends the client's via
    /// [`extend_from_wire`](Self::extend_from_wire), which is what puts
    /// the project ahead of the loadouts. A project maintainer relies on
    /// setting up before any developer's personal hooks do.
    /// [`lifecycle_hooks_teardown`](Self::lifecycle_hooks_teardown) is
    /// the matching reverse order.
    #[must_use]
    pub fn lifecycle_hooks(&self) -> &[ProvenancedHook] {
        &self.lifecycle_hooks
    }

    /// The lifecycle hooks in **teardown order** — the exact reverse of
    /// [`lifecycle_hooks`](Self::lifecycle_hooks), so the project tears
    /// down last, after every loadout that layered on top of it.
    ///
    /// The transitions that use this are `on_detach` and `on_destroy`.
    /// Exposed as its own accessor rather than left to each caller to
    /// `.rev()`: a caller that forgets would silently tear down in setup
    /// order, which no test of a single-contributor session would catch.
    #[must_use]
    pub fn lifecycle_hooks_teardown(&self) -> impl DoubleEndedIterator<Item = &ProvenancedHook> {
        self.lifecycle_hooks.iter().rev()
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
    /// passed the user's policy on the client; items land verbatim
    /// **unless** they conflict with what's already in `self`.
    ///
    /// Atomic: all fallible conversions and all conflict checks run
    /// *before* any mutation. On `Err` (either a malformed wire item
    /// or a `Conflict`), `self` is untouched.
    ///
    /// Per-domain rules at this cross-process merge: vars and
    /// patches error on mismatched values / sources (same name +
    /// same value or same dest + same source is harmless and both
    /// kept); packages deduplicate by name; lifecycle hooks
    /// concatenate.
    ///
    /// # Errors
    ///
    /// - [`ComposeError::InvalidWireItem`] if a wire lifecycle hook
    ///   has no callbacks.
    /// - [`ComposeError::Conflict`] if a wire var or patch disagrees
    ///   with one already in `self`.
    pub(crate) fn extend_from_wire(
        &mut self,
        wire: crate::wire::request::WireContribution,
    ) -> Result<(), ComposeError> {
        // Convert every fallible incoming item up front, into locals,
        // before any mutation of `self`. A failure here leaves
        // `self` untouched.
        let incoming_hooks = wire
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
        let incoming_vars: Vec<SessionVar> = wire.vars.into_iter().map(SessionVar::from).collect();
        let incoming_patches: Vec<SessionPatch> =
            wire.patches.into_iter().map(SessionPatch::from).collect();
        let incoming_packages: Vec<ProvenancedPackage> = wire
            .requested_packages
            .into_iter()
            .map(Into::into)
            .collect();

        // Run conflict checks against the chained union before
        // touching `self`. `Conflict` propagates through
        // `ComposeError::Conflict` via the `#[from]` impl.
        self.check_incoming_conflicts(&incoming_vars, &incoming_patches)?;

        // Checks passed — commit. The client is the sole source of
        // orientation (the daemon passthrough never populates it), so
        // its value is installed rather than merged.
        self.vars.extend(incoming_vars);
        self.patches.extend(incoming_patches);
        self.packages.extend(incoming_packages);
        dedupe_by_name(&mut self.packages, ProvenancedPackage::package);
        self.lifecycle_hooks.extend(incoming_hooks);
        self.orientation = wire.orientation.into();
        Ok(())
    }

    /// Construct a [`Composition`] pre-populated with daemon
    /// pass-through items (packages and lifecycle hooks — neither
    /// has a per-item gate). Packages are deduped by name.
    pub(crate) fn from_daemon_passthrough(
        mut packages: Vec<ProvenancedPackage>,
        lifecycle_hooks: Vec<ProvenancedHook>,
    ) -> Self {
        dedupe_by_name(&mut packages, ProvenancedPackage::package);
        Self {
            vars: Vec::new(),
            patches: Vec::new(),
            packages,
            lifecycle_hooks,
            orientation: Orientation::default(),
        }
    }

    /// Append already-gated vars and patches. Atomic: conflict
    /// checks run against the union before any mutation; on `Err`,
    /// `self` is untouched.
    ///
    /// # Errors
    ///
    /// [`ComposeError::Conflict`] if an incoming var or patch
    /// disagrees with one already in `self`.
    pub(crate) fn extend_with(
        &mut self,
        vars: Vec<SessionVar>,
        patches: Vec<SessionPatch>,
    ) -> Result<(), ComposeError> {
        self.check_incoming_conflicts(&vars, &patches)?;
        self.vars.extend(vars);
        self.patches.extend(patches);
        Ok(())
    }

    /// Run the cross-set var- and patch-mismatch checks against the
    /// union of `self` and the incoming items. Shared by
    /// [`Self::extend_from_wire`] and [`Self::extend_with`] so both
    /// atomic-precheck paths run the exact same conflict semantics.
    fn check_incoming_conflicts(
        &self,
        incoming_vars: &[SessionVar],
        incoming_patches: &[SessionPatch],
    ) -> Result<(), ComposeError> {
        check_var_mismatches(
            self.vars.iter().chain(incoming_vars.iter()),
            |v| v.var().name(),
            |v| v.var().value(),
        )?;
        check_patch_mismatches(
            self.patches.iter().chain(incoming_patches.iter()),
            |p| p.patch().destination(),
            |p| p.patch().host_path().as_str(),
        )?;
        check_patch_prefix_collisions(self.patches.iter().chain(incoming_patches.iter()), |p| {
            p.patch().destination()
        })?;
        Ok(())
    }
}

/// Reconstruct a [`Composition`] from a persisted
/// [`WireComposition`](crate::wire::request::WireComposition)
/// snapshot. The daemon writes the snapshot at composition-assembly
/// time and reads it back at spawn-from-disk so a restart re-applies
/// the exact composition that was approved at `min session activate` time.
///
/// Fallible only on lifecycle hooks (a wire hook with no callbacks
/// is rejected); vars, patches, and packages convert infallibly via
/// their existing `From` impls.
impl TryFrom<crate::wire::request::WireComposition> for Composition {
    type Error = ComposeError;

    fn try_from(wire: crate::wire::request::WireComposition) -> Result<Self, Self::Error> {
        let hooks: Vec<ProvenancedHook> = wire
            .lifecycle_hooks
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|e| ComposeError::InvalidWireItem {
                    what: "lifecycle hook with no callbacks",
                    context: format!("{e}"),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            vars: wire.vars.into_iter().map(Into::into).collect(),
            patches: wire.patches.into_iter().map(Into::into).collect(),
            packages: wire.packages.into_iter().map(Into::into).collect(),
            lifecycle_hooks: hooks,
            orientation: wire.orientation.into(),
        })
    }
}

/// Configuration for the compose pipeline.
///
/// Defaults to symlink-safe behavior (no following) — appropriate for
/// dotfile trees where a symlink may legitimately point outside the
/// patch source.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct ComposeOptions {
    /// If `true`, [`FileSet::resolve`](crate::core::primitives::FileSet::resolve)
    /// follows symlinks while walking patch sources. Off by default.
    pub follow_symlinks: bool,
}

impl ComposeOptions {
    /// Owned-builder setter for [`Self::follow_symlinks`]. Prefer
    /// this over struct-literal syntax so external callers keep
    /// compiling when new fields are added.
    #[must_use]
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }
}

// =====================================================================
// Per-domain gating
// =====================================================================

/// Invoke a var-domain hook on a batch of unapproved items. Returns
/// `(decisions, policy)` where `policy` is the hook's
/// `updated_policy` if provided, else the original. Validates
/// decision count against `view.len()`; a mismatch returns
/// [`ComposeError::HookContract`].
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
    policy: PatchesPolicy,
    view: &[Unapproved<'_, camino::Utf8Path>],
) -> Result<(Vec<ItemDecision>, PatchesPolicy, bool), ComposeError> {
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

/// Invoke the lifecycle-hook-domain hook on a batch of projects whose
/// hooks the policy couldn't decide. Same shape as
/// [`prompt_var_hook`]; one decision per **project**, not per script.
pub(crate) fn prompt_hook_hook(
    hooks: &dyn PolicyHooks,
    policy: crate::core::policy::HooksPolicy,
    view: &[Unapproved<'_, camino::Utf8Path>],
) -> Result<(Vec<ItemDecision>, crate::core::policy::HooksPolicy), ComposeError> {
    match hooks.on_hook_unapproved(policy.clone(), view) {
        HookResult::Abort => Err(ComposeError::Aborted),
        HookResult::Decided {
            decisions,
            updated_policy,
        } => {
            if decisions.len() != view.len() {
                return Err(ComposeError::hook_decision_count_mismatch(
                    HookDomain::Hook,
                    view.len(),
                    decisions.len(),
                ));
            }
            Ok((decisions, updated_policy.unwrap_or(policy)))
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
        // Vars whose value doesn't pull from the user's environment
        // (hardcoded literals, or `inherit-with-default` that fell
        // back to the default) aren't a data-leak vector, so the
        // allow/deny/ignore rules don't apply — send straight to
        // `allowed` without a policy check. The policy exists to
        // gate user data crossing into the sandbox; there's no user
        // data here.
        if !pv.var().carries_user_data() {
            allowed.push(pv);
            continue;
        }
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
                // `IgnoreOnce` is the symmetric partner of `AllowOnce`:
                // silently drop this item for this activation without
                // adding a policy rule. Same downstream effect as a
                // policy `ignore` match.
                ItemDecision::IgnoreOnce => {}
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
///
/// Per-patch `follow_symlinks` is resolved here: any `Some(v)` carried
/// on the [`ProvenancedPatch`] wins; `None` inherits
/// `default_follow_symlinks`. The resolved bool is stamped onto the
/// emitted [`ExpandedProvenancedPatch`] so downstream code doesn't
/// have to re-consult a sidecar map.
pub(crate) fn expand_patch_sources(
    patches: Vec<ProvenancedPatch>,
    gated_vars: &[SessionVar],
    home_fallback: Option<&str>,
    default_follow_symlinks: bool,
) -> Result<Vec<ExpandedProvenancedPatch>, ComposeError> {
    patches
        .into_iter()
        .map(|pp| {
            let (patch, provenance, follow_override) = pp.into_parts();
            let source =
                crate::core::expansion::expand_source(patch.source(), gated_vars, home_fallback)?;
            let follow_symlinks = follow_override.unwrap_or(default_follow_symlinks);
            Ok(ExpandedProvenancedPatch {
                source,
                dest: patch.dest().clone(),
                provenance,
                follow_symlinks,
            })
        })
        .collect()
}

/// Drive the policy pass over a batch of patches.
///
/// `hooks` is `None` for user-only composition — see [`gate_vars`].
pub(crate) fn gate_patches(
    items: Vec<ProvenancedPatch>,
    mut policy: PatchesPolicy,
    hooks: Option<&dyn PolicyHooks>,
    options: ComposeOptions,
    gated_vars: &[SessionVar],
    home_fallback: Option<&str>,
) -> Result<(Vec<SessionPatch>, PatchesPolicy), ComposeError> {
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

    let expanded_patches =
        expand_patch_sources(items, gated_vars, home_fallback, options.follow_symlinks)?;
    let files = enumerate_patch_files(expanded_patches)?;

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
                // `IgnoreOnce` — silent drop for this activation
                // without a policy rule. Mirrors the var-side arm
                // above.
                ItemDecision::IgnoreOnce => {}
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
    // The hooks policy passes straight through: this is the *loadout*
    // composition, and a loadout's hooks are the user's own files. Only
    // project-declared hooks face the gate, on the daemon-response path
    // in `client::handler`.
    let (vars_policy, patches_policy, hooks_policy) = policy.into_parts();
    let (gated_vars, vars_policy) = gate_vars(vars, vars_policy, hooks)?;
    // Conflict detection runs post-gate so that the user's `ignore`
    // policy can drop offending contributors before they're compared.
    // See `Conflict` for the per-domain rules.
    check_var_mismatches(gated_vars.iter(), |v| v.var().name(), |v| v.var().value())?;
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
    check_patch_mismatches(
        gated_patches.iter(),
        |p| p.patch().destination(),
        |p| p.patch().host_path().as_str(),
    )?;
    check_patch_prefix_collisions(gated_patches.iter(), |p| p.patch().destination())?;
    let final_policy = UserPolicy::empty()
        .with_vars(vars_policy)
        .with_patches(patches_policy)
        .with_hooks(hooks_policy);
    let composition = Composition {
        vars: gated_vars,
        patches: gated_patches,
        packages,
        lifecycle_hooks,
        // Orientation never passes through the gate: it is control-plane
        // data the caller attaches outside the composition pipeline (see
        // `UserComposer::with_orientation`).
        orientation: Orientation::default(),
    };
    Ok((composition, final_policy))
}

/// Output of [`contribution_to_pending`]: daemon-collected items in
/// their wire shape, plus the daemon-side stash keyed by
/// [`PendingId`] so [`resume_from_verdict`] can rehydrate provenance
/// from the verdict.
///
/// [`resume_from_verdict`]: crate::daemon::composer::resume_from_verdict
#[derive(Debug, Clone, Default)]
pub(crate) struct PendingTransform {
    pub(crate) wire: WirePending,
    pub(crate) pending_vars: BTreeMap<PendingId, ProvenancedVar>,
    pub(crate) pending_patches: BTreeMap<PendingId, ProvenancedPatch>,
    pub(crate) pending_hooks: BTreeMap<PendingId, ProvenancedHook>,
}

/// Wire-shaped pending payload — the subset of [`PendingTransform`]
/// that crosses the RPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct WirePending {
    pub(crate) vars: Vec<WirePendingVar>,
    pub(crate) patches: Vec<WirePendingPatch>,
    pub(crate) lifecycle_hooks: Vec<WirePendingHook>,
}

/// Convert daemon-collected vars, patches, and lifecycle hooks into
/// their wire pending shape plus a per-item [`PendingId`] stash.
/// Pure: no policy consulted, no env touched.
///
/// Ids are assigned by position within each domain; correlation is
/// per `(domain, id)`.
///
/// # Panics
///
/// If a single domain holds more than `u32::MAX + 1` items.
pub(crate) fn contribution_to_pending(
    vars: Vec<ProvenancedVar>,
    patches: Vec<ProvenancedPatch>,
    lifecycle_hooks: Vec<ProvenancedHook>,
) -> PendingTransform {
    let mut pending_vars: BTreeMap<PendingId, ProvenancedVar> = BTreeMap::new();
    let mut wire_vars: Vec<WirePendingVar> = Vec::with_capacity(vars.len());
    for (i, pv) in vars.into_iter().enumerate() {
        let id = PendingId::new(u32::try_from(i).expect("pending var index fits in u32"));
        // Ship the var's *original* spec, not the composer's resolved
        // value: an inherited var (`Inherit`/`InheritWithDefault`) must
        // be resolved by the client against the *user's* env, never the
        // daemon's. Only `Specified` (a hardcoded literal) carries a
        // real value here; the daemon composer resolves inherited vars
        // against a deferring env (no host lookup), so its `value` for
        // them is a discardable placeholder. `carries_user_data` is
        // recomputed by the client after it resolves, so the bit shipped
        // here is advisory only.
        let carries_user_data = pv.var().carries_user_data();
        wire_vars.push(WirePendingVar {
            id,
            name: pv.var().name().to_string(),
            spec: pv.var().spec().clone().into(),
            source: pv.source().clone().into(),
            carries_user_data,
        });
        pending_vars.insert(id, pv);
    }

    let mut pending_patches: BTreeMap<PendingId, ProvenancedPatch> = BTreeMap::new();
    let mut wire_patches: Vec<WirePendingPatch> = Vec::with_capacity(patches.len());
    for (i, pp) in patches.into_iter().enumerate() {
        let id = PendingId::new(u32::try_from(i).expect("pending patch index fits in u32"));
        wire_patches.push(WirePendingPatch {
            id,
            source_pattern: pp.patch().source().to_string(),
            destination: pp.patch().dest().as_sandbox_path().clone(),
            description: None,
            source: pp.source().clone().into(),
        });
        pending_patches.insert(id, pp);
    }

    // Hooks are stashed by id like vars and patches, rather than
    // shipped as a pass-through list. The daemon must be able to drop
    // the ones the client refuses, and it can only do that if each hook
    // has an id the verdict can name.
    let mut pending_hooks: BTreeMap<PendingId, ProvenancedHook> = BTreeMap::new();
    let mut wire_hooks: Vec<WirePendingHook> = Vec::with_capacity(lifecycle_hooks.len());
    for (i, ph) in lifecycle_hooks.into_iter().enumerate() {
        let id = PendingId::new(u32::try_from(i).expect("pending hook index fits in u32"));
        wire_hooks.push(WirePendingHook {
            id,
            hook: ph.hook().clone().into(),
            source: ph.source().clone().into(),
        });
        pending_hooks.insert(id, ph);
    }

    PendingTransform {
        wire: WirePending {
            vars: wire_vars,
            patches: wire_patches,
            lifecycle_hooks: wire_hooks,
        },
        pending_vars,
        pending_patches,
        pending_hooks,
    }
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
            let policy = PatchesPolicy::empty();
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
            let policy = PatchesPolicy::empty();
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
            let policy = PatchesPolicy::empty().with_deny(["/**/*.pem"]);
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
            let policy = PatchesPolicy::empty().with_deny(["/**/*.pem"]);
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
            let policy = PatchesPolicy::empty().with_ignore(["/**/*.bak"]);
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
            let policy = PatchesPolicy::empty();
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
                None,
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
                None,
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
            let policy = PatchesPolicy::empty();
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

            let policy = PatchesPolicy::empty().with_deny(["~/.ssh/**"]);
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
            let policy = PatchesPolicy::empty().with_deny(["~/.ssh/**"]);
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
                None,
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
                    policy: PatchesPolicy,
                    items: &[Unapproved<'_, camino::Utf8Path>],
                ) -> HookResult<PatchesPolicy> {
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

            let policy = PatchesPolicy::empty();
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
                    policy: PatchesPolicy,
                    items: &[Unapproved<'_, camino::Utf8Path>],
                ) -> HookResult<PatchesPolicy> {
                    let updated = policy.with_deny(["$NOT_RESOLVED/*"]);
                    HookResult::decided_with_policy(
                        vec![ItemDecision::UseRule; items.len()],
                        updated,
                    )
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
            let policy = PatchesPolicy::empty();
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
            let policy = PatchesPolicy::empty().with_deny([format!("{denied_dir}/**")]);
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
            let policy = PatchesPolicy::empty().with_allow([format!("{root}/**")]);
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

            let policy = PatchesPolicy::empty().with_allow([format!("{link}/**")]);
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
                check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path())
                    .is_ok()
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
                check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path())
                    .is_ok()
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
                check_patch_prefix_collisions(&items, |p| p.patch().dest().as_sandbox_path())
                    .is_ok()
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
                check_patch_prefix_collisions(&[b, a], |p| p.patch().dest().as_sandbox_path())
                    .is_err()
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
            let second =
                ProvenancedPackage::new("helix", Source::UserLoadout { name: "dev".into() });
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
            let right =
                contribution_with(vec![], vec![], vec![], vec![hook("echo hi", user_source())]);
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
                None,
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
            let policy = UserPolicy::empty()
                .with_vars(VarsPolicy::empty().try_with_ignore(["EDITOR"]).unwrap());
            let (composition, _policy) = compose_contribution(
                contribution,
                &[],
                policy,
                Some(&PanicHooks),
                ComposeOptions::default(),
                None,
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
            WireLifecycleHook, WireOrientation, WirePackageRef, WireProvenancedHook,
            WireResolvedPatch, WireResolvedVar, WireSessionPatch, WireSessionVar, WireSource,
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

        fn wire_with(
            vars: Vec<WireSessionVar>,
            patches: Vec<WireSessionPatch>,
        ) -> WireContribution {
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
}
