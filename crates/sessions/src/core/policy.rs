//! Policy types: per-domain `VarsPolicy` and `PatchPolicy`, plus the
//! top-level `UserPolicy` that bundles them.
//!
//! [`UserPolicy`] bundles the per-domain policies — [`VarsPolicy`] for
//! environment variables and [`PatchPolicy`] for file patches. Both
//! gate every declaration regardless of origin; user-origin
//! declarations from a [`Loadout`] don't need to be explicitly
//! `allow`-listed (they auto-pass that check), but `ignore` and
//! `deny` apply to them just as they do to project- and
//! package-origin items.
//!
//! Kept separate from [`Loadout`] on purpose: the user's policy is
//! about what they let other sources contribute, not about what *they*
//! contribute. Composing multiple Loadouts doesn't compose policy.
//!
//! [`Loadout`]: crate::core::loadout::Loadout
//!
//! # Example
//!
//! ```toml
//! [vars]
//! allow  = ["MY_APP_*", "RUST_*"]
//! deny   = ["AWS_*", "*_TOKEN"]
//! ignore = ["_*"]
//!
//! [patches]
//! allow  = ["~/.config/**", "/etc/xdg/**"]
//! deny   = ["~/.ssh/**", "**/*.pem"]
//! ignore = ["**/.DS_Store"]
//! ```

use crate::core::decision::{CheckOutcome, Decision};
use crate::core::primitives::{FileSet, VarError};
use crate::core::source::{Provenanced, Source};

// =====================================================================
// VarNameGlobs
// =====================================================================

/// A set of glob patterns matching variable names.
///
/// Patterns are compiled at construction time so malformed ones fail at
/// config load. Used by [`VarsPolicy`] to express allow/deny/ignore
/// lists.
#[derive(Clone, Debug)]
pub struct VarNameGlobs {
    patterns: Vec<String>,
    compiled: Vec<globset::Glob>,
    set: globset::GlobSet,
}

impl Default for VarNameGlobs {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            compiled: Vec::new(),
            set: globset::GlobSet::empty(),
        }
    }
}

impl VarNameGlobs {
    /// Construct an empty set. Useful as the start of a builder chain.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct from raw patterns.
    ///
    /// # Errors
    ///
    /// Returns [`VarError::InvalidGlob`] if any pattern fails to parse.
    pub fn try_new<I, S>(patterns: I) -> Result<Self, VarError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let raw: Vec<String> = patterns.into_iter().map(Into::into).collect();
        let compiled = raw
            .iter()
            .map(|p| {
                globset::Glob::new(p).map_err(|source| VarError::InvalidGlob {
                    pattern: p.clone(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let set = build_set(&compiled)?;
        Ok(Self {
            patterns: raw,
            compiled,
            set,
        })
    }

    /// Append a single pattern.
    ///
    /// # Errors
    ///
    /// Returns [`VarError::InvalidGlob`] if the pattern fails to parse;
    /// the set is consumed.
    pub fn with_pattern(self, pattern: impl Into<String>) -> Result<Self, VarError> {
        let pattern = pattern.into();
        let glob = globset::Glob::new(&pattern).map_err(|source| VarError::InvalidGlob {
            pattern: pattern.clone(),
            source,
        })?;
        let mut new = self;
        new.patterns.push(pattern);
        new.compiled.push(glob);
        new.set = build_set(&new.compiled)?;
        Ok(new)
    }

    /// The original pattern strings (suitable for re-serialization).
    #[must_use]
    pub fn raw_patterns(&self) -> &[String] {
        &self.patterns
    }

    /// The compiled glob patterns.
    #[must_use]
    pub fn globs(&self) -> &[globset::Glob] {
        &self.compiled
    }

    /// Returns `true` if there are no patterns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// `true` iff any pattern in this set matches `name`.
    #[must_use]
    pub fn is_match(&self, name: &str) -> bool {
        self.set.is_match(name)
    }
}

fn build_set(globs: &[globset::Glob]) -> Result<globset::GlobSet, VarError> {
    let mut b = globset::GlobSetBuilder::new();
    for g in globs {
        b.add(g.clone());
    }
    // Individual `Glob::new` validation does not bound the *combined*
    // regex, which can hit `regex` crate size/complexity limits.
    b.build()
        .map_err(|source| VarError::InvalidGlobSet { source })
}

impl PartialEq for VarNameGlobs {
    fn eq(&self, other: &Self) -> bool {
        self.patterns == other.patterns
    }
}
impl Eq for VarNameGlobs {}

impl std::hash::Hash for VarNameGlobs {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.patterns.hash(state);
    }
}

impl serde::Serialize for VarNameGlobs {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.patterns.serialize(ser)
    }
}

impl<'de> serde::Deserialize<'de> for VarNameGlobs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Many(Vec<String>),
            One(String),
        }
        let patterns = match Repr::deserialize(deserializer)? {
            Repr::Many(v) => v,
            Repr::One(s) => vec![s],
        };
        Self::try_new(patterns).map_err(serde::de::Error::custom)
    }
}

// =====================================================================
// VarsPolicy
// =====================================================================

/// Policy gating which variable declarations are honored.
///
/// Applied at the session-construction layer. Precedence is the same
/// for every origin: `ignore` first (silent), then `deny` (reject),
/// then origin-aware allow (auto-allow for user-origin, otherwise
/// require an `allow` match or prompt).
///
/// - **User-origin** (variables coming from a [`Loadout`]):
///   `ignore` drops, `deny` rejects, otherwise auto-allowed. The
///   user doesn't need to `allow`-list their own loadout items.
/// - **Project- and Package-origin**: `ignore` drops, `deny` rejects,
///   then `allow` must match or the item prompts.
///
/// [`Loadout`]: crate::core::loadout::Loadout
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VarsPolicy {
    #[serde(default, skip_serializing_if = "VarNameGlobs::is_empty")]
    allow: VarNameGlobs,
    #[serde(default, skip_serializing_if = "VarNameGlobs::is_empty")]
    deny: VarNameGlobs,
    #[serde(default, skip_serializing_if = "VarNameGlobs::is_empty")]
    ignore: VarNameGlobs,
}

impl VarsPolicy {
    /// Construct an empty policy. Build it up with [`Self::with_allow`],
    /// [`Self::with_deny`], and [`Self::with_ignore`]:
    ///
    /// ```
    /// use sessions::core::policy::{VarNameGlobs, VarsPolicy};
    /// let p = VarsPolicy::empty()
    ///     .with_allow(VarNameGlobs::try_new(["MY_APP_*", "RUST_*"]).unwrap())
    ///     .with_deny(VarNameGlobs::try_new(["AWS_*"]).unwrap());
    /// assert_eq!(p.allow().raw_patterns().len(), 2);
    /// assert!(p.ignore().is_empty());
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace the `allow` set.
    #[must_use]
    pub fn with_allow(self, allow: VarNameGlobs) -> Self {
        Self { allow, ..self }
    }

    /// Replace the `deny` set.
    #[must_use]
    pub fn with_deny(self, deny: VarNameGlobs) -> Self {
        Self { deny, ..self }
    }

    /// Replace the `ignore` set.
    #[must_use]
    pub fn with_ignore(self, ignore: VarNameGlobs) -> Self {
        Self { ignore, ..self }
    }

    /// Replace the `allow` set, constructing it from raw patterns.
    ///
    /// # Errors
    ///
    /// Returns [`VarError::InvalidGlob`] if any pattern fails to parse.
    pub fn try_with_allow<I, S>(self, patterns: I) -> Result<Self, VarError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(self.with_allow(VarNameGlobs::try_new(patterns)?))
    }

    /// Replace the `deny` set, constructing it from raw patterns.
    ///
    /// # Errors
    ///
    /// Returns [`VarError::InvalidGlob`] if any pattern fails to parse.
    pub fn try_with_deny<I, S>(self, patterns: I) -> Result<Self, VarError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(self.with_deny(VarNameGlobs::try_new(patterns)?))
    }

    /// Replace the `ignore` set, constructing it from raw patterns.
    ///
    /// # Errors
    ///
    /// Returns [`VarError::InvalidGlob`] if any pattern fails to parse.
    pub fn try_with_ignore<I, S>(self, patterns: I) -> Result<Self, VarError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(self.with_ignore(VarNameGlobs::try_new(patterns)?))
    }

    /// Names non-user declarations may set. User-origin declarations
    /// don't need to match this — they auto-pass the allow step (but
    /// are still subject to `deny` and `ignore`).
    #[must_use]
    pub fn allow(&self) -> &VarNameGlobs {
        &self.allow
    }

    /// Names no declaration may set, regardless of origin.
    #[must_use]
    pub fn deny(&self) -> &VarNameGlobs {
        &self.deny
    }

    /// Names to silently drop without prompting, regardless of origin.
    #[must_use]
    pub fn ignore(&self) -> &VarNameGlobs {
        &self.ignore
    }

    /// Categorize a single variable against this policy.
    ///
    /// Precedence: `ignore` first (silent drop), then `deny` (reject
    /// regardless of origin), then the origin-aware allow step. For
    /// user-origin items ([`Source::UserLoadout`]), the allow step
    /// auto-passes — the user doesn't need to allow-list their own
    /// loadout entries. For every other source, `allow` must match
    /// or the item routes to `NeedsApproval`.
    ///
    /// `item` reports its provenance via [`Provenanced`]; the composer
    /// constructs `T` types that carry their own source, so the caller
    /// doesn't have to clone-and-borrow at the call site.
    ///
    /// Provenance of the *matched pattern* is not reported here; surface
    /// that via a separate inspection command.
    ///
    /// [`Source::UserLoadout`]: crate::core::source::Source::UserLoadout
    /// [`Provenanced`]: crate::core::source::Provenanced
    #[must_use]
    pub fn check<T: Provenanced>(&self, name: &str, item: T) -> CheckOutcome<T> {
        if self.ignore.is_match(name) {
            return CheckOutcome::Decided(Decision::Ignored);
        }
        if self.deny.is_match(name) {
            return CheckOutcome::Decided(Decision::Denied(item));
        }
        if matches!(item.source(), Source::UserLoadout { .. }) {
            return CheckOutcome::Decided(Decision::Allowed(item));
        }
        if self.allow.is_match(name) {
            CheckOutcome::Decided(Decision::Allowed(item))
        } else {
            CheckOutcome::NeedsApproval(item)
        }
    }
}

// =====================================================================
// PatchPolicy
// =====================================================================

/// Policy gating which patches are honored, checked per source file
/// after the patch's [`FileSet`] is walked. The patch's `dest` is
/// not matched; only the enumerated source paths are.
///
/// - **User-origin patches** (from a [`Loadout`]): `ignore` drops,
///   `deny` rejects, otherwise auto-allowed.
/// - **Project- and Package-origin patches**: `ignore` drops, `deny`
///   rejects, then `allow` must match — otherwise routes to a
///   prompt via [`PolicyHooks`](crate::core::hooks::PolicyHooks).
///
/// Precedence: `ignore` first, then `deny`, then origin-aware
/// `allow`. Patterns may contain `~/` or `$VAR`; expansion happens
/// at session construction (see [`crate::core::expansion`]) and
/// stored patterns retain their raw form so the policy round-trips
/// losslessly.
///
/// [`Loadout`]: crate::core::loadout::Loadout
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatchPolicy {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    allow: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    deny: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    ignore: Vec<String>,
}

/// Accepts either a single pattern (bare string) or a list of patterns.
fn deserialize_one_or_many<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Repr::deserialize(d)? {
        Repr::One(s) => vec![s],
        Repr::Many(v) => v,
    })
}

impl PatchPolicy {
    /// Construct an empty policy. Build it up with [`Self::with_allow`],
    /// [`Self::with_deny`], and [`Self::with_ignore`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace the `allow` set with raw pattern strings. Patterns are
    /// not validated until expansion happens at gate time.
    #[must_use]
    pub fn with_allow<I, S>(self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow: patterns.into_iter().map(Into::into).collect(),
            ..self
        }
    }

    /// Replace the `deny` set with raw pattern strings.
    #[must_use]
    pub fn with_deny<I, S>(self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            deny: patterns.into_iter().map(Into::into).collect(),
            ..self
        }
    }

    /// Replace the `ignore` set with raw pattern strings.
    #[must_use]
    pub fn with_ignore<I, S>(self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            ignore: patterns.into_iter().map(Into::into).collect(),
            ..self
        }
    }

    /// Raw patterns non-user patches **may** target. User-origin
    /// patches auto-pass this step (but are still subject to `deny`
    /// and `ignore`).
    #[must_use]
    pub fn allow(&self) -> &[String] {
        &self.allow
    }

    /// Raw patterns no patch may target, regardless of origin.
    #[must_use]
    pub fn deny(&self) -> &[String] {
        &self.deny
    }

    /// Raw patterns silently dropped without prompting, regardless
    /// of origin.
    #[must_use]
    pub fn ignore(&self) -> &[String] {
        &self.ignore
    }

    /// Expand the raw patterns against `resolved_vars` and produce an
    /// [`ExpandedPatchPolicy`] suitable for matching.
    ///
    /// Every pattern is run through
    /// [`crate::core::expansion::expand_source`]; the first failure stops
    /// the expansion and is returned.
    ///
    /// # Errors
    ///
    /// Returns the first [`crate::core::expansion::ExpandError`] produced
    /// by any pattern.
    pub fn expand_with(
        &self,
        resolved_vars: &(impl crate::core::expansion::VarLookup + ?Sized),
        home_fallback: Option<&str>,
    ) -> Result<ExpandedPatchPolicy, crate::core::expansion::ExpandError> {
        let expand_one =
            |raws: &[String]| -> Result<Vec<FileSet>, crate::core::expansion::ExpandError> {
                raws.iter()
                    .map(|r| crate::core::expansion::expand_source(r, resolved_vars, home_fallback))
                    .collect()
            };
        let allow = expand_one(&self.allow)?;
        let deny = expand_one(&self.deny)?;
        let ignore = expand_one(&self.ignore)?;
        Ok(ExpandedPatchPolicy::from_expanded(allow, deny, ignore))
    }
}

// =====================================================================
// UserPolicy
// =====================================================================

/// The user's policy for what projects and packages may contribute to a
/// session.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserPolicy {
    #[serde(default, skip_serializing_if = "vars_policy_is_default")]
    vars: VarsPolicy,
    #[serde(default, skip_serializing_if = "patch_policy_is_default")]
    patches: PatchPolicy,
}

impl UserPolicy {
    /// Construct an empty policy — equivalent to [`Default::default`].
    /// Build it up via [`Self::with_vars`] and [`Self::with_patches`]:
    ///
    /// ```
    /// use sessions::core::policy::{UserPolicy, VarNameGlobs, VarsPolicy};
    ///
    /// let p = UserPolicy::empty().with_vars(
    ///     VarsPolicy::empty()
    ///         .with_allow(VarNameGlobs::try_new(["MY_APP_*"]).unwrap()),
    /// );
    /// assert_eq!(p.vars().allow().raw_patterns(), &["MY_APP_*"]);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace the variables policy.
    #[must_use]
    pub fn with_vars(self, vars: VarsPolicy) -> Self {
        Self { vars, ..self }
    }

    /// Replace the patches policy.
    #[must_use]
    pub fn with_patches(self, patches: PatchPolicy) -> Self {
        Self { patches, ..self }
    }

    /// The variables policy in effect.
    #[must_use]
    pub fn vars(&self) -> &VarsPolicy {
        &self.vars
    }

    /// The patches policy in effect.
    #[must_use]
    pub fn patches(&self) -> &PatchPolicy {
        &self.patches
    }

    /// Consume the policy and return the underlying narrow policies.
    ///
    /// Used by the composition pipeline, which moves each narrow
    /// policy into the corresponding per-domain gate and rebuilds a
    /// `UserPolicy` from the (possibly updated) results.
    #[must_use]
    pub fn into_parts(self) -> (VarsPolicy, PatchPolicy) {
        (self.vars, self.patches)
    }
}

fn vars_policy_is_default(p: &VarsPolicy) -> bool {
    p == &VarsPolicy::default()
}

fn patch_policy_is_default(p: &PatchPolicy) -> bool {
    p == &PatchPolicy::default()
}

// =====================================================================
// ExpandedPatchPolicy
// =====================================================================

/// A [`PatchPolicy`] with all `~/` and `$VAR` references expanded into
/// concrete glob patterns against a set of resolved session vars.
///
/// Produced from a raw [`PatchPolicy`] via
/// [`PatchPolicy::expand_with`] at the patch gate's main entry point;
/// the gate matches against this form, not the raw policy. The raw
/// policy is preserved separately so it can round-trip through
/// serialization unchanged.
#[derive(Clone, Debug)]
pub struct ExpandedPatchPolicy {
    allow: Vec<FileSet>,
    deny: Vec<FileSet>,
    ignore: Vec<FileSet>,
}

impl ExpandedPatchPolicy {
    /// Construct an `ExpandedPatchPolicy` from already-expanded
    /// lists. Crate-internal so external callers must go through
    /// [`PatchPolicy::expand_with`] and can't bypass expansion.
    pub(crate) fn from_expanded(
        allow: Vec<FileSet>,
        deny: Vec<FileSet>,
        ignore: Vec<FileSet>,
    ) -> Self {
        Self {
            allow,
            deny,
            ignore,
        }
    }

    /// Expanded `allow` patterns.
    #[must_use]
    pub fn allow(&self) -> &[FileSet] {
        &self.allow
    }

    /// Expanded `deny` patterns.
    #[must_use]
    pub fn deny(&self) -> &[FileSet] {
        &self.deny
    }

    /// Expanded `ignore` patterns.
    #[must_use]
    pub fn ignore(&self) -> &[FileSet] {
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
    /// **Precedence within one path:** `ignore` first (silent drop),
    /// then `deny` (reject regardless of origin), then the
    /// origin-aware allow step. For user-origin items
    /// ([`Source::UserLoadout`]) the allow step auto-passes; for
    /// every other source `allow` must match or the path routes to
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
        if filesets_match(&self.deny, path) {
            return PathDecision::Denied;
        }
        if matches!(source, Source::UserLoadout { .. }) {
            return PathDecision::Allowed;
        }
        if filesets_match(&self.allow, path) {
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
pub(crate) enum PathDecision {
    Allowed,
    Ignored,
    Denied,
    NeedsApproval,
}

impl PathDecision {
    /// Combine two per-path decisions into one. Precedence (most
    /// restrictive first):
    /// `Denied` > `Ignored` > `NeedsApproval` > `Allowed`.
    pub(crate) fn combine(self, other: Self) -> Self {
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

fn filesets_match(sets: &[FileSet], path: &camino::Utf8Path) -> bool {
    sets.iter().any(|fs| fs.is_match(path))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(sets: &[String]) -> Vec<&str> {
        sets.iter().map(String::as_str).collect()
    }

    // =================================================================
    // VarsPolicy tests
    // =================================================================

    #[test]
    fn vars_policy_full_example() {
        let src = r#"
            allow  = ["MY_APP_*", "RUST_*"]
            deny   = ["AWS_*", "*_TOKEN"]
            ignore = ["_*"]
        "#;
        let policy: VarsPolicy = toml::from_str(src).unwrap();
        assert_eq!(policy.allow().raw_patterns().len(), 2);
        assert_eq!(policy.deny().raw_patterns().len(), 2);
        assert_eq!(policy.ignore().raw_patterns().len(), 1);
    }

    #[test]
    fn vars_policy_defaults_when_omitted() {
        let policy: VarsPolicy = toml::from_str("").unwrap();
        assert!(policy.allow().is_empty());
        assert!(policy.deny().is_empty());
        assert!(policy.ignore().is_empty());
    }

    #[test]
    fn vars_policy_accepts_bare_string_for_each_field() {
        let policy: VarsPolicy = toml::from_str(r#"deny = "AWS_*""#).unwrap();
        assert_eq!(policy.deny().raw_patterns(), &["AWS_*"]);
    }

    #[test]
    fn vars_policy_rejects_invalid_glob() {
        let err = toml::from_str::<VarsPolicy>(r#"allow = "[bad""#).unwrap_err();
        assert!(err.to_string().contains("invalid glob"), "got: {err}");
    }

    // ---- Builder ergonomics ----

    #[test]
    fn var_name_globs_with_pattern_chains() {
        let g = VarNameGlobs::empty()
            .with_pattern("MY_APP_*")
            .unwrap()
            .with_pattern("RUST_*")
            .unwrap();
        assert_eq!(g.raw_patterns(), &["MY_APP_*", "RUST_*"]);
        assert_eq!(g.globs().len(), 2);
    }

    #[test]
    fn var_name_globs_with_pattern_reports_invalid() {
        let err = VarNameGlobs::empty().with_pattern("[bad").unwrap_err();
        assert!(matches!(err, VarError::InvalidGlob { .. }), "got: {err:?}");
    }

    #[test]
    fn vars_policy_builder_assembles_independent_fields() {
        let p = VarsPolicy::empty()
            .with_allow(VarNameGlobs::try_new(["MY_APP_*"]).unwrap())
            .with_deny(VarNameGlobs::try_new(["AWS_*"]).unwrap())
            .with_ignore(VarNameGlobs::try_new(["_*"]).unwrap());
        assert_eq!(p.allow().raw_patterns(), &["MY_APP_*"]);
        assert_eq!(p.deny().raw_patterns(), &["AWS_*"]);
        assert_eq!(p.ignore().raw_patterns(), &["_*"]);
    }

    #[test]
    fn vars_policy_with_methods_replace_rather_than_merge() {
        let p = VarsPolicy::empty()
            .with_allow(VarNameGlobs::try_new(["A"]).unwrap())
            .with_allow(VarNameGlobs::try_new(["B"]).unwrap());
        assert_eq!(p.allow().raw_patterns(), &["B"]);
    }

    #[test]
    fn vars_policy_skips_default_fields_on_serialize() {
        // Only `allow` is set; serialized output must omit `deny` / `ignore`.
        let p = VarsPolicy::empty().try_with_allow(["A"]).unwrap();
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("allow"), "expected allow, got: {s}");
        assert!(!s.contains("deny"), "expected no deny, got: {s}");
        assert!(!s.contains("ignore"), "expected no ignore, got: {s}");
    }

    // ---- Pattern-accepting builder variants ----

    #[test]
    fn vars_policy_try_with_methods_accept_pattern_iterators() {
        let p = VarsPolicy::empty()
            .try_with_allow(["MY_APP_*", "RUST_*"])
            .unwrap()
            .try_with_deny(["AWS_*"])
            .unwrap()
            .try_with_ignore(["_*"])
            .unwrap();
        assert_eq!(p.allow().raw_patterns(), &["MY_APP_*", "RUST_*"]);
        assert_eq!(p.deny().raw_patterns(), &["AWS_*"]);
        assert_eq!(p.ignore().raw_patterns(), &["_*"]);
    }

    #[test]
    fn vars_policy_try_with_allow_propagates_invalid_glob() {
        let err = VarsPolicy::empty().try_with_allow(["[bad"]).unwrap_err();
        assert!(matches!(err, VarError::InvalidGlob { .. }), "got: {err:?}");
    }

    // =================================================================
    // PatchPolicy tests
    // =================================================================

    #[test]
    fn patch_policy_full_example() {
        let src = r#"
            allow = ["~/.config/**", "/etc/xdg/**"]
            deny = ["~/.ssh/**", "**/*.pem"]
            ignore = ["**/.DS_Store"]
        "#;
        let policy: PatchPolicy = toml::from_str(src).unwrap();
        assert_eq!(patterns(policy.allow()), ["~/.config/**", "/etc/xdg/**"]);
        assert_eq!(patterns(policy.deny()), ["~/.ssh/**", "**/*.pem"]);
        assert_eq!(patterns(policy.ignore()), ["**/.DS_Store"]);
    }

    #[test]
    fn patch_policy_defaults_when_omitted() {
        let policy: PatchPolicy = toml::from_str("").unwrap();
        assert!(policy.allow().is_empty());
        assert!(policy.deny().is_empty());
        assert!(policy.ignore().is_empty());
    }

    #[test]
    fn patch_policy_accepts_bare_string_for_each_field() {
        let policy: PatchPolicy = toml::from_str(r#"deny = "~/.ssh/**""#).unwrap();
        assert_eq!(patterns(policy.deny()), ["~/.ssh/**"]);
    }

    #[test]
    fn patch_policy_builder_methods() {
        let p = PatchPolicy::empty()
            .with_allow(["~/.config/**"])
            .with_deny(["~/.ssh/**", "**/*.pem"])
            .with_ignore(["**/.DS_Store"]);
        assert_eq!(patterns(p.allow()), ["~/.config/**"]);
        assert_eq!(patterns(p.deny()), ["~/.ssh/**", "**/*.pem"]);
        assert_eq!(patterns(p.ignore()), ["**/.DS_Store"]);
    }

    #[test]
    fn patch_policy_stores_invalid_pattern_without_validating() {
        // Patterns are no longer parsed at construction time; an invalid
        // glob is held verbatim and only fails at expansion-time, after
        // var substitution gets a chance to fix it. This documents that
        // shift.
        let p = PatchPolicy::empty().with_allow(["[bad"]);
        assert_eq!(patterns(p.allow()), ["[bad"]);
    }

    #[test]
    fn patch_policy_skips_empty_fields_on_serialize() {
        let p = PatchPolicy::empty().with_allow(["A"]);
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("allow"), "expected allow, got: {s}");
        assert!(!s.contains("deny"), "expected no deny, got: {s}");
        assert!(!s.contains("ignore"), "expected no ignore, got: {s}");
    }

    // ---- PatchPolicy::expand_with ----

    /// Build a `ResolvedVar` with the given name + value.
    fn sv(name: &str, value: &str) -> crate::core::primitives::ResolvedVar {
        crate::core::primitives::ResolvedVar::resolve_with(
            name.into(),
            crate::core::primitives::VarValue::specified(value),
            |_| Err(std::env::VarError::NotPresent),
        )
        .unwrap()
    }

    /// Each list expands independently. Patterns referencing the same
    /// `HOME` get the same substituted prefix.
    #[test]
    fn expand_with_substitutes_all_three_lists() {
        let policy = PatchPolicy::empty()
            .with_allow(["~/cfg/**"])
            .with_deny(["$HOME/.ssh/**"])
            .with_ignore(["~/.DS_Store"]);
        let vars = [sv("HOME", "/h")];
        let expanded = policy.expand_with(vars.as_slice(), None).unwrap();
        let pats = |sets: &[FileSet]| -> Vec<String> {
            sets.iter().map(|f| f.pattern().to_owned()).collect()
        };
        assert_eq!(pats(expanded.allow()), ["/h/cfg/**"]);
        assert_eq!(pats(expanded.deny()), ["/h/.ssh/**"]);
        assert_eq!(pats(expanded.ignore()), ["/h/.DS_Store"]);
    }

    /// A pattern in any list referencing an unresolved var bubbles
    /// out as `ExpandError::UndefinedVar`. Short-circuits on the first
    /// failure.
    #[test]
    fn expand_with_propagates_first_undefined_var() {
        let policy = PatchPolicy::empty()
            .with_allow(["/etc/**"])
            .with_deny(["$NOPE/*"]);
        let vars: [crate::core::primitives::ResolvedVar; 0] = [];
        let err = policy.expand_with(vars.as_slice(), None).unwrap_err();
        assert!(
            matches!(
                err,
                crate::core::expansion::ExpandError::UndefinedVar { ref name }
                    if name == "NOPE"
            ),
            "got: {err:?}",
        );
    }

    /// A policy with no expansion-needing patterns resolves against an
    /// empty var set with no error. This is the dominant fast path —
    /// no `~/` or `$VAR` anywhere means no lookup pressure on the
    /// resolved-vars set at all.
    #[test]
    fn expand_with_empty_vars_works_when_no_expansion_needed() {
        let policy = PatchPolicy::empty()
            .with_allow(["/etc/xdg/**"])
            .with_deny(["/**/*.pem"])
            .with_ignore(["/**/.DS_Store"]);
        let vars: [crate::core::primitives::ResolvedVar; 0] = [];
        let expanded = policy.expand_with(vars.as_slice(), None).unwrap();
        // Patterns pass through globset intact.
        assert_eq!(expanded.allow().len(), 1);
        assert_eq!(expanded.deny().len(), 1);
        assert_eq!(expanded.ignore().len(), 1);
    }

    // =================================================================
    // UserPolicy tests
    // =================================================================

    #[test]
    fn empty_round_trips_through_toml() {
        let p = UserPolicy::empty();
        let s = toml::to_string(&p).unwrap();
        let parsed: UserPolicy = toml::from_str(&s).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn deserializes_with_both_sections() {
        let src = r#"
            [vars]
            allow = ["MY_APP_*"]
            deny  = ["AWS_*"]

            [patches]
            allow = ["~/.config/**"]
            deny  = ["~/.ssh/**"]
        "#;
        let p: UserPolicy = toml::from_str(src).unwrap();
        assert_eq!(p.vars().allow().raw_patterns(), &["MY_APP_*"]);
        assert_eq!(p.vars().deny().raw_patterns(), &["AWS_*"]);
        assert_eq!(p.patches().allow(), ["~/.config/**"]);
        assert_eq!(p.patches().deny(), ["~/.ssh/**"]);
    }

    #[test]
    fn deserializes_with_only_one_section() {
        let src = r#"
            [vars]
            allow = ["X"]
        "#;
        let p: UserPolicy = toml::from_str(src).unwrap();
        assert_eq!(p.vars().allow().raw_patterns(), &["X"]);
        assert_eq!(p.patches(), &PatchPolicy::default());
    }

    #[test]
    fn skips_default_sections_on_serialize() {
        let p = UserPolicy::empty()
            .with_vars(VarsPolicy::empty().with_allow(VarNameGlobs::try_new(["X"]).unwrap()));
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("[vars"), "expected vars section, got: {s}");
        assert!(
            !s.contains("[patches"),
            "expected no patches section, got: {s}"
        );
    }

    // =================================================================
    // PathDecision combinator tests
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
}
