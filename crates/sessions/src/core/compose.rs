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
/// package composable's `contribute`, so lifting the loop bodies into
/// one helper prevents the impls from drifting when a new primitive
/// lands. For packages, patches, and hooks the only per-source
/// difference is the [`Source`] tag stamped on every produced item.
///
/// **Vars are the exception.** [`Loadout::contribute`] passes empty
/// maps for both var arguments and resolves its own vars through a
/// private `resolve_var_declaration`, because a loadout treats a bare
/// [`VarValue::Inherit`] the host hasn't set as a warn-and-drop.
/// Everything that *does* route vars through here — project and
/// package composables — gets [`ResolvedVar::resolve_with`]'s strict
/// rule instead, where that same case is a hard error. Don't read
/// this helper as the single definition of var semantics; it is the
/// strict one of two.
///
/// [`Loadout::contribute`]: crate::core::loadout::Loadout::contribute
/// [`VarValue::Inherit`]: crate::core::primitives::VarValue::Inherit
/// [`ResolvedVar::resolve_with`]: crate::core::primitives::ResolvedVar::resolve_with
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

/// What a batch of patterns expands against, beyond the session's
/// resolved variables: the `HOME` fallback for the `~` prefix, and the
/// directory the user's loadouts were read from.
///
/// The compose-side counterpart to
/// [`expansion::Anchors`](crate::core::expansion::Anchors), which is
/// per-*pattern* and already resolved. This one is per-*batch* and
/// still holds the loadouts directory rather than one loadout's
/// subdirectory of it, because which subdirectory applies is a property
/// of each patch's own [`Source`] —
/// [`expand_patch_sources`] derives it per item.
///
/// The two fields travel together through the whole patch pipeline
/// (`compose_contribution` → `gate_patches` → `expand_patch_sources`),
/// so they ride as one value rather than as a pair of positional
/// `Option`s that are easy to transpose.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub(crate) struct PatchAnchors<'a> {
    /// `HOME` for the `~` / `~/…` prefix, when the session's vars don't
    /// carry one. Explicit `$HOME` references stay strict.
    pub(crate) home: Option<&'a str>,
    /// Where the user's loadout files were read from. `None` — the
    /// daemon-response path, which sees no loadouts — means no patch in
    /// the batch can resolve `$LOADOUT_ROOT`.
    pub(crate) loadouts_dir: Option<&'a paths::HostAbsPath>,
}

impl<'a> PatchAnchors<'a> {
    /// Anchors carrying only a `HOME` fallback — the shape every
    /// caller that composes no loadouts wants.
    #[must_use]
    pub(crate) fn home(home: Option<&'a str>) -> Self {
        Self {
            home,
            loadouts_dir: None,
        }
    }

    /// Add the directory the loadouts in this batch were read from.
    #[must_use]
    pub(crate) fn with_loadouts_dir(
        mut self,
        loadouts_dir: Option<&'a paths::HostAbsPath>,
    ) -> Self {
        self.loadouts_dir = loadouts_dir;
        self
    }

    /// The directory a patch declared by `provenance` anchors
    /// `$LOADOUT_ROOT` at — its own loadout's, or `None` for a patch no
    /// loadout declared (and for a batch with no loadouts directory).
    ///
    /// Returned owned rather than folded straight into an
    /// [`Anchors`](crate::core::expansion::Anchors): those borrow their
    /// anchor strings, so the directory has to outlive them at the call
    /// site.
    fn loadout_root(self, provenance: &Source) -> Option<paths::HostAbsPath> {
        self.loadouts_dir.and_then(|d| provenance.loadout_dir(d))
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

/// What the policy decided about one name.
///
/// The value-free half of [`Decision`]: a caller that has not resolved
/// its values yet — or must not, until the policy has spoken — gets a
/// verdict it can act on without handing anything to the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameVerdict {
    /// The policy permits this name.
    Allowed,
    /// Drop it silently.
    Ignored,
}

/// A bare name's provenance, for [`VarsPolicy::check`]. Carries no
/// value: [`gate_names`] exists precisely so a caller need not have one.
struct NameItem<'a> {
    source: &'a Source,
}

impl Provenanced for NameItem<'_> {
    fn source(&self) -> &Source {
        self.source
    }
}

/// Drive the policy pass over a batch of `(name, source)` pairs and
/// return one [`NameVerdict`] per input, in order, plus the policy as
/// the hook may have amended it.
///
/// This is the gate itself — classify, refer what is undecided to
/// `hooks`, apply what comes back — with values factored out.
/// [`gate_vars`] is this function plus the value plumbing, and callers
/// that must decide *before* reading a value (a task's `env_vars` are
/// resolved out of the invoking user's shell, so reading an unapproved
/// one defeats the gate) call this directly.
///
/// `hooks` is `None` for user-only composition — all items are expected
/// to auto-decide.
///
/// # Errors
///
/// - [`ComposeError::Denied`] — a `deny` rule matched. Returned from the
///   first denial found, before any hook is consulted, so a forbidden
///   name is never preceded by a prompt about its neighbours.
/// - [`ComposeError::HookRequired`] — an item needed approval and there
///   was no hook to ask.
/// - [`ComposeError::Aborted`] — the hook cancelled.
/// - [`ComposeError::HookContract`] — the hook returned the wrong number
///   of decisions, or answered `UseRule` for an item the policy still
///   cannot decide.
///
/// [`VarsPolicy::check`]: crate::core::policy::VarsPolicy::check
pub fn gate_names(
    items: &[(&str, &Source)],
    mut policy: VarsPolicy,
    hooks: Option<&dyn PolicyHooks>,
) -> Result<(Vec<NameVerdict>, VarsPolicy), ComposeError> {
    // A denial ends the batch where it is found, before any hook runs.
    // `deny` is the emergency stop: an operator who has forbidden a name
    // should not first be prompted about its neighbours, approve one,
    // have that rule written to `user_policy.toml`, and only then be told
    // the composition was never going to succeed.
    let denied = |name: &str, source: &Source| ComposeError::Denied {
        what: name.to_owned(),
        from: source.clone(),
    };
    let verdict_of = |d: &Decision<NameItem<'_>>| match d {
        Decision::Allowed(_) => Some(NameVerdict::Allowed),
        Decision::Ignored => Some(NameVerdict::Ignored),
        Decision::Denied(_) => None,
    };

    // Pass 1: categorize. An undecided item is seeded `Ignored` and
    // queued; pass 3 overwrites every one of them. The placeholder is
    // fail-closed on purpose — should a future edit ever leave one
    // unwritten, the caller drops the name rather than carrying it.
    let mut verdicts: Vec<NameVerdict> = Vec::with_capacity(items.len());
    let mut unapproved: Vec<usize> = Vec::new();
    for (i, (name, source)) in items.iter().enumerate() {
        match policy.check(name, NameItem { source }) {
            CheckOutcome::Decided(d) => match verdict_of(&d) {
                Some(v) => verdicts.push(v),
                None => return Err(denied(name, source)),
            },
            CheckOutcome::NeedsApproval(_) => {
                unapproved.push(i);
                verdicts.push(NameVerdict::Ignored);
            }
        }
    }

    if !unapproved.is_empty() {
        let Some(hooks) = hooks else {
            let i = unapproved[0];
            return Err(ComposeError::HookRequired {
                what: items[i].0.to_owned(),
                from: items[i].1.clone(),
            });
        };
        // Pass 2: prompt.
        let view: Vec<Unapproved<'_, str>> = unapproved
            .iter()
            .map(|&i| Unapproved {
                item: items[i].0,
                source: items[i].1,
            })
            .collect();
        let (decisions, new_policy) = prompt_var_hook(hooks, policy, &view)?;
        policy = new_policy;
        // Pass 3: apply.
        for (&i, decision) in unapproved.iter().zip(decisions) {
            let (name, source) = items[i];
            verdicts[i] = match decision {
                ItemDecision::AllowOnce => NameVerdict::Allowed,
                ItemDecision::IgnoreOnce => NameVerdict::Ignored,
                ItemDecision::UseRule => match policy.check(name, NameItem { source }) {
                    CheckOutcome::Decided(d) => match verdict_of(&d) {
                        Some(v) => v,
                        None => return Err(denied(name, source)),
                    },
                    CheckOutcome::NeedsApproval(_) => {
                        return Err(ComposeError::use_rule_undecided(
                            HookDomain::Var,
                            format!("variable `{name}`"),
                        ));
                    }
                },
            };
        }
    }

    Ok((verdicts, policy))
}

/// Drive the policy pass over a batch of vars.
///
/// `hooks` is `None` for user-only composition — all items are
/// expected to auto-decide. Any item that reaches the `NeedsApproval`
/// branch with no hook surfaces as [`ComposeError::HookRequired`].
pub(crate) fn gate_vars(
    items: Vec<ProvenancedVar>,
    policy: VarsPolicy,
    hooks: Option<&dyn PolicyHooks>,
) -> Result<(Vec<SessionVar>, VarsPolicy), ComposeError> {
    // Vars whose value doesn't pull from the user's environment
    // (hardcoded literals, or `inherit-with-default` that fell back to
    // the default) aren't a data-leak vector, so the allow/deny/ignore
    // rules don't apply — they never reach the gate. The policy exists
    // to gate user data crossing into the sandbox; there's no user data
    // here.
    let gated: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, pv)| pv.var().carries_user_data())
        .map(|(i, _)| i)
        .collect();

    // Scoped so the borrows of `items` end before it is consumed below.
    let (verdicts, policy) = {
        let pairs: Vec<(&str, &Source)> = gated
            .iter()
            .map(|&i| (items[i].var().name(), items[i].source()))
            .collect();
        gate_names(&pairs, policy, hooks)?
    };

    let mut verdict_at: Vec<Option<NameVerdict>> = vec![None; items.len()];
    for (&i, v) in gated.iter().zip(verdicts) {
        verdict_at[i] = Some(v);
    }

    // Walked in input order, so the emitted list keeps the order the
    // composer built it in — an ungated literal does not jump ahead of
    // a gated var declared before it.
    let mut allowed: Vec<ProvenancedVar> = Vec::with_capacity(items.len());
    for (pv, verdict) in items.into_iter().zip(&verdict_at) {
        match verdict {
            // Never gated: skipped the policy entirely.
            None | Some(NameVerdict::Allowed) => allowed.push(pv),
            Some(NameVerdict::Ignored) => {}
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
/// `anchors` carries the batch-wide `HOME` fallback and the directory
/// the user's loadout files were read from; each patch a loadout
/// declared expands `$LOADOUT_ROOT` against its own subdirectory of
/// that (see [`PatchAnchors::loadout_root`]). A patch from a
/// non-loadout source has no such anchor, so a `$LOADOUT_ROOT`
/// reference there is an error rather than a path pointing at someone
/// else's tree.
///
/// Per-patch `follow_symlinks` is resolved here: any `Some(v)` carried
/// on the [`ProvenancedPatch`] wins; `None` inherits
/// `default_follow_symlinks`. The resolved bool is stamped onto the
/// emitted [`ExpandedProvenancedPatch`] so downstream code doesn't
/// have to re-consult a sidecar map.
pub(crate) fn expand_patch_sources(
    patches: Vec<ProvenancedPatch>,
    gated_vars: &[SessionVar],
    anchors: PatchAnchors<'_>,
    default_follow_symlinks: bool,
) -> Result<Vec<ExpandedProvenancedPatch>, ComposeError> {
    patches
        .into_iter()
        .map(|pp| {
            let (patch, provenance, follow_override) = pp.into_parts();
            let loadout_root = anchors.loadout_root(&provenance);
            let pattern_anchors = crate::core::expansion::Anchors::home(anchors.home)
                .with_loadout_root(loadout_root.as_ref().map(paths::HostAbsPath::as_str));
            let source =
                crate::core::expansion::expand_source(patch.source(), gated_vars, pattern_anchors)?;
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
/// `anchors` is what the patterns expand against — see
/// [`expand_patch_sources`].
pub(crate) fn gate_patches(
    items: Vec<ProvenancedPatch>,
    mut policy: PatchesPolicy,
    hooks: Option<&dyn PolicyHooks>,
    options: ComposeOptions,
    gated_vars: &[SessionVar],
    anchors: PatchAnchors<'_>,
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
    let mut expanded = policy.expand_with(gated_vars, anchors.home)?;

    let expanded_patches =
        expand_patch_sources(items, gated_vars, anchors, options.follow_symlinks)?;
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
            expanded = policy.expand_with(gated_vars, anchors.home)?;
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
/// `anchors` carries the `HOME` fallback and, for `$LOADOUT_ROOT`, the
/// directory the loadouts were read from. Only the client composes
/// loadouts, so the daemon side leaves that unset.
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
    anchors: PatchAnchors<'_>,
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
    // `SessionVar` — no env fallback. The two exceptions come from
    // `anchors` rather than the var set: the tilde prefix (`~/...`)
    // falls back to its `home` if the loadout didn't declare a `HOME`
    // var, and `$LOADOUT_ROOT` resolves under its `loadouts_dir`.
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
        anchors,
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
mod tests;
