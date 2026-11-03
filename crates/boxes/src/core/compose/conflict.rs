//! Merge-time conflict-detection helpers extracted from [`super`].
//!
//! These fns are the *only* place per-domain merge rules live; they are
//! called by `Composition::extend_from_wire`, `Composition::check_incoming_conflicts`,
//! `contribution_to_pending`, and `Contribution::merge`.

use super::{Conflict, Provenanced, Source};

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
pub(crate) fn check_var_mismatches<'a, T: Provenanced + 'a>(
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
pub(crate) fn check_patch_mismatches<'a, T: Provenanced + 'a>(
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
pub(crate) fn check_patch_prefix_collisions<'a, T: Provenanced + 'a>(
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
pub(crate) fn dedupe_by_name<T>(items: &mut Vec<T>, name: impl Fn(&T) -> &str) {
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
