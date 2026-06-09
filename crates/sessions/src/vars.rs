//! Environment variable primitives: how a session declares which variables
//! to set, how those declarations are sourced, and which the session
//! policy permits.
//!
//! # Names
//!
//! Two flavors of name are recognized:
//!
//! - [`StrictVarName`] — POSIX-shaped (`[A-Z_][A-Z0-9_]*`). The default; what
//!   the bare-string wire form decodes into. Catches typos like `MY VAR`
//!   at config-load time.
//! - [`LenientVarName`] — anything the Linux kernel accepts (no `=`, no
//!   NUL). Loud, explicit opt-in via the `vars_lenient` array form on
//!   [`crate::loadout::Loadout`]; never produced by the bare-string path.
//!
//! [`VarName`] is the sum of the two for places that need to hold either.
//!
//! # Values
//!
//! [`VarValue`] is what the variable should resolve to:
//!
//! - [`Inherit`](VarValue::Inherit) — pass through from the parent env.
//! - [`InheritWithDefault`](VarValue::InheritWithDefault) — pass through
//!   from the parent, fall back to `default` if unset.
//! - [`Specified`](VarValue::Specified) — set to a specific value,
//!   ignoring the parent.
//!
//! # Provenance
//!
//! The primitives in this module are origin-free. A variable's provenance
//! is determined by which source file it appears in — a [`Loadout`] is
//! always user-originated; equivalent project / package primitives carry
//! their own origins by virtue of where they live. The session-construction
//! layer combines the three sources and attaches origin per-source.
//!
//! [`Loadout`]: crate::loadout::Loadout
//!
//! # Example
//!
//! ```toml
//! [vars]
//! EDITOR = "vim"                                # → Specified
//! HOME   = { inherit = true }                   # → Inherit
//! LANG   = { inherit = true, default = "C" }    # → InheritWithDefault
//!
//! # Lenient names go in their own array — POSIX-strict by default.
//! [[vars_lenient]]
//! name  = "weird-thing"
//! value = "x"
//!
//! [vars_policy]
//! allow  = ["MY_APP_*", "RUST_*"]
//! deny   = ["AWS_*", "*_TOKEN", "LD_PRELOAD"]
//! ignore = ["_*"]
//! ```

use core::fmt;
use std::str::FromStr;

// =====================================================================
// Errors
// =====================================================================

/// Errors produced when constructing var primitives.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A var name was empty.
    #[error("variable name must not be empty")]
    EmptyName,
    /// A var name failed POSIX validation (used by [`StrictVarName`]).
    #[error(
        "variable name `{0}` is not POSIX-shaped (expected `[A-Z_][A-Z0-9_]*`); \
         use the `vars_lenient` form for non-POSIX names"
    )]
    NotPosixName(String),
    /// A var name contained `=` or NUL, which the kernel won't accept.
    #[error("variable name `{0}` contains `=` or NUL, which the kernel rejects")]
    InvalidLenientName(String),
    /// A pattern string failed to parse as a glob.
    #[error("invalid glob pattern `{pattern}`: {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    /// Resolving an inherited variable's value via the environment lookup
    /// (default: [`std::env::var`]) failed.
    #[error("unable to get value of environment variable {name}: {source}")]
    ResolutionFailure {
        name: String,
        #[source]
        source: std::env::VarError,
    },
    /// Compiling the precomputed [`globset::GlobSet`] matcher failed.
    /// Each individual pattern was already validated by
    /// [`globset::Glob::new`]; this error covers failures of the
    /// *combined* regex — typically size or complexity limits when
    /// many patterns alternate together.
    #[error("failed to compile combined glob matcher: {source}")]
    InvalidGlobSet {
        #[source]
        source: globset::Error,
    },
}

// =====================================================================
// Names
// =====================================================================

/// A POSIX-shaped environment variable name: `[A-Z_][A-Z0-9_]*`.
///
/// Stricter than what the kernel will accept, intentionally — the strict
/// form catches typos at config-load time and matches the convention
/// every well-behaved program in the ecosystem expects.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StrictVarName(String);

impl StrictVarName {
    /// Construct after validating against POSIX rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyName`] for empty input, or
    /// [`Error::NotPosixName`] if the name contains anything outside
    /// `[A-Z_][A-Z0-9_]*`.
    pub fn try_new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return Err(Error::EmptyName);
        };
        if !(first.is_ascii_uppercase() || first == '_') {
            return Err(Error::NotPosixName(s));
        }
        for c in chars {
            if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
                return Err(Error::NotPosixName(s));
            }
        }
        Ok(Self(s))
    }

    /// Borrow the underlying name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the newtype and return the underlying [`String`].
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for StrictVarName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StrictVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for StrictVarName {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for StrictVarName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for StrictVarName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// A lenient environment variable name: anything the Linux kernel
/// accepts (no `=`, no NUL byte).
///
/// Use sparingly — programs reading the env almost universally assume
/// POSIX-shaped names. Reach for this only when integrating with an
/// existing system that already publishes weird names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LenientVarName(String);

impl LenientVarName {
    /// Construct after rejecting `=` and NUL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyName`] for empty input, or
    /// [`Error::InvalidLenientName`] if the name contains `=` or NUL.
    pub fn try_new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        if s.is_empty() {
            return Err(Error::EmptyName);
        }
        if s.contains('=') || s.contains('\0') {
            return Err(Error::InvalidLenientName(s));
        }
        Ok(Self(s))
    }

    /// Borrow the underlying name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the newtype and return the underlying [`String`].
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for LenientVarName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LenientVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for LenientVarName {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for LenientVarName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for LenientVarName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// One entry in the lenient-vars array form.
///
/// Used by [`crate::loadout::Loadout`] as the wire-form representation
/// of a single non-POSIX variable. The map form (`vars = { ... }`) can't
/// carry the strict/lenient distinction in its keys, so lenient names
/// require a separate array (`[[vars_lenient]]`); each element is one
/// of these.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LenientVarEntry {
    name: LenientVarName,
    value: VarValue,
}

impl LenientVarEntry {
    /// Construct an entry from a pre-validated name.
    #[must_use]
    pub fn new(name: LenientVarName, value: VarValue) -> Self {
        Self { name, value }
    }

    /// Construct an entry from a raw string name, validating it.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] from [`LenientVarName::try_new`] if `name`
    /// is empty or contains `=` / NUL.
    pub fn try_new(name: impl Into<String>, value: VarValue) -> Result<Self, Error> {
        Ok(Self {
            name: LenientVarName::try_new(name)?,
            value,
        })
    }

    /// The variable's name.
    #[must_use]
    pub fn name(&self) -> &LenientVarName {
        &self.name
    }

    /// The resolution rule.
    #[must_use]
    pub fn value(&self) -> &VarValue {
        &self.value
    }

    /// Consume the entry and return its components.
    #[must_use]
    pub fn into_parts(self) -> (LenientVarName, VarValue) {
        (self.name, self.value)
    }
}

impl From<(LenientVarName, VarValue)> for LenientVarEntry {
    fn from((name, value): (LenientVarName, VarValue)) -> Self {
        Self { name, value }
    }
}

/// A variable name — either [`Strict`](Self::Strict) (POSIX) or
/// [`Lenient`](Self::Lenient) (Linux-permissive).
///
/// Used in unified contexts where either kind may appear (e.g.
/// [`crate::loadout::Loadout::all_vars`]). The wire form on
/// [`crate::loadout::Loadout`] itself keeps strict and lenient in
/// separate fields so a bare-string TOML key can never accidentally
/// smuggle a non-POSIX name through.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VarName {
    /// POSIX-shaped.
    Strict(StrictVarName),
    /// Linux-permissive.
    Lenient(LenientVarName),
}

impl VarName {
    /// Borrow the underlying name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Strict(n) => n.as_str(),
            Self::Lenient(n) => n.as_str(),
        }
    }
}

impl fmt::Display for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<StrictVarName> for VarName {
    fn from(n: StrictVarName) -> Self {
        Self::Strict(n)
    }
}

impl From<LenientVarName> for VarName {
    fn from(n: LenientVarName) -> Self {
        Self::Lenient(n)
    }
}

// =====================================================================
// VarValue
// =====================================================================

/// The resolution rule for a variable: inherited, inherited with a
/// fallback, or set to a literal value.
///
/// # Wire form
///
/// Untagged — the shape distinguishes the variant:
///
/// ```toml
/// EDITOR = "vim"                                # → Specified
/// HOME   = { inherit = true }                   # → Inherit
/// LANG   = { inherit = true, default = "C" }    # → InheritWithDefault
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VarValue {
    /// Pass through from the parent environment.
    Inherit,
    /// Pass through; fall back to `default` if the parent is unset.
    InheritWithDefault {
        /// Value to use when the parent env has no entry.
        default: String,
    },
    /// Set to `value`, ignoring the parent environment.
    Specified {
        /// Literal value.
        value: String,
    },
}

impl VarValue {
    /// Construct a [`Specified`](Self::Specified) value.
    #[must_use]
    pub fn specified(value: impl Into<String>) -> Self {
        Self::Specified {
            value: value.into(),
        }
    }

    /// Construct an [`InheritWithDefault`](Self::InheritWithDefault) value.
    #[must_use]
    pub fn inherit_with_default(default: impl Into<String>) -> Self {
        Self::InheritWithDefault {
            default: default.into(),
        }
    }
}

impl serde::Serialize for VarValue {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            Self::Specified { value } => ser.serialize_str(value),
            Self::Inherit => {
                let mut st = ser.serialize_struct("Inherit", 1)?;
                st.serialize_field("inherit", &true)?;
                st.end()
            }
            Self::InheritWithDefault { default } => {
                let mut st = ser.serialize_struct("InheritWithDefault", 2)?;
                st.serialize_field("inherit", &true)?;
                st.serialize_field("default", default)?;
                st.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for VarValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Specified(String),
            Inherit {
                inherit: bool,
                #[serde(default)]
                default: Option<String>,
            },
        }
        match Repr::deserialize(deserializer)? {
            Repr::Specified(value) => Ok(Self::Specified { value }),
            Repr::Inherit {
                inherit: true,
                default: Some(default),
            } => Ok(Self::InheritWithDefault { default }),
            Repr::Inherit {
                inherit: true,
                default: None,
            } => Ok(Self::Inherit),
            Repr::Inherit { inherit: false, .. } => Err(serde::de::Error::custom(
                "`inherit = false` is not a meaningful variable specification; \
                 omit the variable entirely instead",
            )),
        }
    }
}

// =====================================================================
// VarsPolicy
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
    /// Returns [`Error::InvalidGlob`] if any pattern fails to parse.
    pub fn try_new<I, S>(patterns: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let raw: Vec<String> = patterns.into_iter().map(Into::into).collect();
        let compiled = raw
            .iter()
            .map(|p| {
                globset::Glob::new(p).map_err(|source| Error::InvalidGlob {
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
    /// Returns [`Error::InvalidGlob`] if the pattern fails to parse;
    /// the set is consumed.
    pub fn with_pattern(self, pattern: impl Into<String>) -> Result<Self, Error> {
        let pattern = pattern.into();
        let glob = globset::Glob::new(&pattern).map_err(|source| Error::InvalidGlob {
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

fn build_set(globs: &[globset::Glob]) -> Result<globset::GlobSet, Error> {
    let mut b = globset::GlobSetBuilder::new();
    for g in globs {
        b.add(g.clone());
    }
    // Individual `Glob::new` validation does not bound the *combined*
    // regex, which can hit `regex` crate size/complexity limits.
    b.build().map_err(|source| Error::InvalidGlobSet { source })
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

/// Policy gating which variable declarations are honored.
///
/// Applied at the session-construction layer based on a declaration's
/// source:
///
/// - **User-origin** (variables coming from a [`Loadout`]): only
///   [`ignore`](Self::ignore) applies. `allow` and `deny` are bypassed
///   — the user is the policy for their own declarations.
/// - **Project- and Package-origin**: all three fields apply. A
///   declaration is honored iff its name matches `allow`, does not match
///   `deny`, and does not match `ignore`. Matching `ignore` is silent;
///   matching `deny` is an error/prompt; matching neither `allow` nor
///   `ignore` triggers a permission prompt.
///
/// [`Loadout`]: crate::loadout::Loadout
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
    /// use sessions::vars::{VarNameGlobs, VarsPolicy};
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
    /// Returns [`Error::InvalidGlob`] if any pattern fails to parse.
    pub fn try_with_allow<I, S>(self, patterns: I) -> Result<Self, Error>
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
    /// Returns [`Error::InvalidGlob`] if any pattern fails to parse.
    pub fn try_with_deny<I, S>(self, patterns: I) -> Result<Self, Error>
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
    /// Returns [`Error::InvalidGlob`] if any pattern fails to parse.
    pub fn try_with_ignore<I, S>(self, patterns: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(self.with_ignore(VarNameGlobs::try_new(patterns)?))
    }

    /// Names non-user declarations may set. Does not apply to
    /// user-origin declarations.
    #[must_use]
    pub fn allow(&self) -> &VarNameGlobs {
        &self.allow
    }

    /// Names non-user declarations must not set. Does not apply to
    /// user-origin declarations.
    #[must_use]
    pub fn deny(&self) -> &VarNameGlobs {
        &self.deny
    }

    /// Names to silently drop without prompting. Applies to every
    /// origin, user-origin included.
    #[must_use]
    pub fn ignore(&self) -> &VarNameGlobs {
        &self.ignore
    }

    /// Categorize a single variable against this policy.
    ///
    /// Precedence: `ignore` first, then a source-aware branch. For
    /// user-origin items ([`Source::UserLoadout`]), `allow` and `deny`
    /// do not apply — anything not ignored is implicitly allowed. For
    /// every other source, the precedence continues `deny` → `allow` →
    /// `NeedsApproval`.
    ///
    /// `item` reports its provenance via [`Provenanced`]; the resolver
    /// constructs `T` types that carry their own source, so the caller
    /// doesn't have to clone-and-borrow at the call site.
    ///
    /// Provenance of the *matched pattern* is not reported here; surface
    /// that via a separate inspection command.
    ///
    /// [`Source::UserLoadout`]: crate::composable::Source::UserLoadout
    /// [`Provenanced`]: crate::composable::Provenanced
    #[must_use]
    pub fn check<T: crate::composable::Provenanced>(
        &self,
        name: &str,
        item: T,
    ) -> crate::composable::CheckOutcome<T> {
        use crate::composable::{CheckOutcome, Decision, Source};
        if self.ignore.is_match(name) {
            return CheckOutcome::Decided(Decision::Ignored);
        }
        if matches!(item.source(), Source::UserLoadout { .. }) {
            return CheckOutcome::Decided(Decision::Allowed(item));
        }
        if self.deny.is_match(name) {
            CheckOutcome::Decided(Decision::Denied(item))
        } else if self.allow.is_match(name) {
            CheckOutcome::Decided(Decision::Allowed(item))
        } else {
            CheckOutcome::NeedsApproval(item)
        }
    }
}

/// A variable name paired with the value it should resolve to after
/// applying [`VarValue`] semantics (inheriting from the environment,
/// falling back to a default, or taking a literal).
///
/// Both fields are raw strings: by the time a session is being
/// activated, the OS is the next consumer and doesn't care about our
/// strict/lenient name distinction. The newtype invariants are still
/// upheld upstream — `ResolvedVar` only stores the post-resolution
/// snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedVar {
    name: String,
    value: String,
}

impl ResolvedVar {
    /// The variable's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The resolved value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Resolve a variable against an arbitrary environment-lookup function.
    /// The thread-able shape lets tests pin every branch without touching
    /// the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ResolutionFailure`] if `lookup` returns an error
    /// that the variant's semantics surface (every error for
    /// [`VarValue::Inherit`]; only [`std::env::VarError::NotUnicode`] for
    /// [`VarValue::InheritWithDefault`]).
    pub fn resolve_with<F>(name: String, value: VarValue, lookup: F) -> Result<Self, Error>
    where
        F: FnOnce(&str) -> Result<String, std::env::VarError>,
    {
        let resolved_value = match value {
            VarValue::Specified { value } => value,
            VarValue::Inherit => lookup(&name).map_err(|source| Error::ResolutionFailure {
                name: name.clone(),
                source,
            })?,
            VarValue::InheritWithDefault { default } => match lookup(&name) {
                Ok(value) => value,
                Err(std::env::VarError::NotPresent) => default,
                Err(source @ std::env::VarError::NotUnicode(_)) => {
                    return Err(Error::ResolutionFailure {
                        name: name.clone(),
                        source,
                    });
                }
            },
        };
        Ok(Self {
            name,
            value: resolved_value,
        })
    }

    /// Resolve a variable against the process environment via
    /// [`std::env::var`]. Sugar for [`Self::resolve_with`] with the
    /// default lookup.
    ///
    /// # Errors
    ///
    /// See [`Self::resolve_with`].
    pub fn resolve(name: String, value: VarValue) -> Result<Self, Error> {
        Self::resolve_with(name, value, |l| std::env::var(l))
    }
}

impl TryFrom<(StrictVarName, VarValue)> for ResolvedVar {
    type Error = Error;
    fn try_from((name, value): (StrictVarName, VarValue)) -> Result<Self, Error> {
        Self::resolve(name.into_inner(), value)
    }
}

impl TryFrom<LenientVarEntry> for ResolvedVar {
    type Error = Error;
    fn try_from(entry: LenientVarEntry) -> Result<Self, Self::Error> {
        let (name, value) = entry.into_parts();
        Self::resolve(name.into_inner(), value)
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct Wrap<T> {
        x: T,
    }

    fn parse<T: serde::de::DeserializeOwned>(toml_str: &str) -> T {
        toml::from_str::<Wrap<T>>(toml_str).unwrap().x
    }

    // ---- StrictVarName ----

    #[test]
    fn strict_accepts_canonical_names() {
        for n in ["FOO", "_BAR", "MY_APP_HOME", "X1", "_"] {
            assert!(StrictVarName::try_new(n).is_ok(), "rejected: {n}");
        }
    }

    #[test]
    fn strict_rejects_non_posix_shapes() {
        for n in ["", "lowercase", "1FOO", "FOO-BAR", "FOO BAR", "FOO=BAR"] {
            assert!(StrictVarName::try_new(n).is_err(), "accepted: {n}");
        }
    }

    #[test]
    fn strict_deserialize_rejects_lowercase() {
        let err = toml::from_str::<Wrap<StrictVarName>>(r#"x = "foo""#).unwrap_err();
        assert!(err.to_string().contains("POSIX"), "got: {err}");
    }

    #[test]
    fn strict_round_trips_through_toml() {
        let original = StrictVarName::try_new("MY_APP_HOME").unwrap();
        let s = toml::to_string(&Wrap {
            x: original.clone(),
        })
        .unwrap();
        let parsed: StrictVarName = parse(&s);
        assert_eq!(parsed, original);
    }

    // ---- LenientVarName ----

    #[test]
    fn lenient_accepts_unusual_but_kernel_legal_names() {
        for n in ["weird-thing", "lowercase", "1foo", "foo.bar"] {
            assert!(LenientVarName::try_new(n).is_ok(), "rejected: {n}");
        }
    }

    #[test]
    fn lenient_rejects_kernel_illegal_names() {
        assert!(LenientVarName::try_new("").is_err());
        assert!(LenientVarName::try_new("foo=bar").is_err());
        assert!(LenientVarName::try_new("foo\0bar").is_err());
    }

    // ---- VarValue ----

    #[test]
    fn varvalue_rejects_inherit_false() {
        let err = toml::from_str::<Wrap<VarValue>>(r"x = { inherit = false }").unwrap_err();
        assert!(err.to_string().contains("inherit = false"), "got: {err}");
    }

    #[test]
    fn varvalue_specified_round_trips_as_bare_string() {
        let v = VarValue::Specified {
            value: "vim".into(),
        };
        let s = toml::to_string(&Wrap { x: v.clone() }).unwrap();
        assert_eq!(s.trim(), r#"x = "vim""#);
        let parsed: VarValue = parse(&s);
        assert_eq!(parsed, v);
    }

    #[test]
    fn varvalue_inherit_round_trips_as_table() {
        for original in [
            VarValue::Inherit,
            VarValue::InheritWithDefault {
                default: "C".into(),
            },
        ] {
            let s = toml::to_string(&Wrap {
                x: original.clone(),
            })
            .unwrap();
            let parsed: VarValue = parse(&s);
            assert_eq!(parsed, original);
        }
    }

    // ---- VarsPolicy ----

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
        assert!(matches!(err, Error::InvalidGlob { .. }), "got: {err:?}");
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
        assert!(matches!(err, Error::InvalidGlob { .. }), "got: {err:?}");
    }

    // ---- VarValue helpers ----

    #[test]
    fn varvalue_specified_helper() {
        let v = VarValue::specified("vim");
        assert_eq!(
            v,
            VarValue::Specified {
                value: "vim".into()
            }
        );
    }

    #[test]
    fn varvalue_inherit_with_default_helper() {
        let v = VarValue::inherit_with_default("C");
        assert_eq!(
            v,
            VarValue::InheritWithDefault {
                default: "C".into()
            }
        );
    }

    // ---- Name FromStr ----

    #[test]
    fn strict_var_name_parses_via_from_str() {
        let n: StrictVarName = "EDITOR".parse().unwrap();
        assert_eq!(n.as_str(), "EDITOR");
        let err = "lowercase".parse::<StrictVarName>().unwrap_err();
        assert!(matches!(err, Error::NotPosixName(_)));
    }

    #[test]
    fn lenient_var_name_parses_via_from_str() {
        let n: LenientVarName = "weird-thing".parse().unwrap();
        assert_eq!(n.as_str(), "weird-thing");
        let err = "foo=bar".parse::<LenientVarName>().unwrap_err();
        assert!(matches!(err, Error::InvalidLenientName(_)));
    }

    // ---- LenientVarEntry helpers ----

    #[test]
    fn lenient_entry_try_new_validates_name() {
        let e = LenientVarEntry::try_new("weird-thing", VarValue::specified("x")).unwrap();
        assert_eq!(e.name().as_str(), "weird-thing");
    }

    #[test]
    fn lenient_entry_try_new_rejects_bad_name() {
        let err = LenientVarEntry::try_new("a=b", VarValue::specified("x")).unwrap_err();
        assert!(matches!(err, Error::InvalidLenientName(_)));
    }

    #[test]
    fn lenient_entry_from_tuple() {
        let n = LenientVarName::try_new("x").unwrap();
        let v = VarValue::specified("1");
        let e: LenientVarEntry = (n.clone(), v.clone()).into();
        assert_eq!(e.name(), &n);
        assert_eq!(e.value(), &v);
    }

    // ---- ResolvedVar ----

    fn make_lookup<'a>(
        entries: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&str) -> Result<String, std::env::VarError> + 'a {
        move |name| {
            entries
                .iter()
                .find_map(|(k, v)| (*k == name).then(|| (*v).to_owned()))
                .ok_or(std::env::VarError::NotPresent)
        }
    }

    #[test]
    fn resolved_var_specified_does_not_consult_lookup() {
        let r = ResolvedVar::resolve_with("EDITOR".into(), VarValue::specified("hx"), |_| {
            panic!("lookup must not be called for Specified")
        })
        .unwrap();
        assert_eq!(r.name(), "EDITOR");
        assert_eq!(r.value(), "hx");
    }

    #[test]
    fn resolved_var_inherit_returns_lookup_value() {
        let lookup = make_lookup(&[("LANG", "en_US.UTF-8")]);
        let r = ResolvedVar::resolve_with("LANG".into(), VarValue::Inherit, lookup).unwrap();
        assert_eq!(r.value(), "en_US.UTF-8");
    }

    #[test]
    fn resolved_var_inherit_surfaces_not_present_as_error() {
        let lookup = make_lookup(&[]);
        let err = ResolvedVar::resolve_with("LANG".into(), VarValue::Inherit, lookup).unwrap_err();
        assert!(matches!(
            err,
            Error::ResolutionFailure {
                source: std::env::VarError::NotPresent,
                ..
            },
        ));
    }

    #[test]
    fn resolved_var_inherit_with_default_falls_back_when_unset() {
        let lookup = make_lookup(&[]);
        let r =
            ResolvedVar::resolve_with("LANG".into(), VarValue::inherit_with_default("C"), lookup)
                .unwrap();
        assert_eq!(r.value(), "C");
    }

    #[test]
    fn resolved_var_inherit_with_default_prefers_env_value() {
        let lookup = make_lookup(&[("LANG", "en_US.UTF-8")]);
        let r =
            ResolvedVar::resolve_with("LANG".into(), VarValue::inherit_with_default("C"), lookup)
                .unwrap();
        assert_eq!(r.value(), "en_US.UTF-8");
    }

    #[test]
    fn resolved_var_inherit_with_default_surfaces_not_unicode_as_error() {
        use std::ffi::OsString;
        let lookup = |_: &str| Err(std::env::VarError::NotUnicode(OsString::from("bad")));
        let err =
            ResolvedVar::resolve_with("LANG".into(), VarValue::inherit_with_default("C"), lookup)
                .unwrap_err();
        assert!(matches!(
            err,
            Error::ResolutionFailure {
                source: std::env::VarError::NotUnicode(_),
                ..
            },
        ));
    }

    #[test]
    fn resolved_var_error_source_chain_includes_var_error() {
        let lookup = make_lookup(&[]);
        let err = ResolvedVar::resolve_with("LANG".into(), VarValue::Inherit, lookup).unwrap_err();
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "expected source on ResolutionFailure");
    }
}
