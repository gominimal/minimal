//! Origin-free primitives for vars and patches.
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
//!   [`crate::core::loadout::Loadout`]; never produced by the bare-string path.
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
//! The primitives in this module are origin-free. A variable's or
//! patch's provenance is determined by which source file it appears in
//! — a [`Loadout`] is always user-originated; equivalent project /
//! package primitives carry their own origins by virtue of where they
//! live. The session-construction layer combines the three sources and
//! attaches origin per-source.
//!
//! [`Loadout`]: crate::core::loadout::Loadout
//!
//! # The `FileSet` primitive
//!
//! [`FileSet`] is the description of "which files" — a single glob pattern,
//! reused for patch sources, allowlists, denylists, and ignore lists. The
//! wire form is always a bare string; lists of patterns live one level
//! up (at the patches array or in policy fields).
//!
//! Path expansion is split by responsibility:
//!
//! - **`FileSet` itself** stores patterns as written. No expansion at
//!   construction or matching time.
//! - **The composer** (see [`crate::core::compose`]) expands leading
//!   `~` in patch *source* patterns and in
//!   [`PatchesPolicy`](crate::core::policy::PatchesPolicy) patterns at the
//!   start of the patch gate, against the composer's `HOME` env lookup.
//!   Patterns retain their `~` form in returned policies for
//!   round-trippability.
//! - **[`PatchDest`] needs no expansion.** Every destination is
//!   implicitly relative to the sandbox user's home directory; `~`
//!   and absolute paths are rejected at construction.
//! - **The apply layer** is responsible for `$VAR` expansion and
//!   canonicalization across the board.

use core::fmt;
use std::str::FromStr;

use camino::{Utf8Component, Utf8PathBuf};
use paths::{HostAbsPath, HostPath, SandboxRelPath};

// =====================================================================
// Errors
// =====================================================================

/// Errors produced when constructing var primitives.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VarError {
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

/// Errors produced when constructing patch types.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    /// A pattern string failed to parse as a glob.
    #[error("invalid glob pattern `{pattern}`: {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    /// A patch destination was empty.
    #[error("patch destination must not be empty")]
    EmptyDest,
    /// A patch destination contained a `..` component, which is rejected
    /// before path canonicalization to avoid traversal attacks.
    #[error("patch destination `{0}` must not contain `..` components")]
    DestTraversal(Utf8PathBuf),
    /// A patch destination decoded to an absolute path. Dests must be
    /// relative to the sandbox/home root.
    #[error("Patch destination must be relative to the home directory: {0}")]
    AbsoluteDestPath(#[source] paths::Error),
    /// A directory walk failed while enumerating a [`FileSet`]'s
    /// matches — typically due to permission denial or a missing
    /// directory.
    #[error("Failed to walk {root}: {source}")]
    WalkFailure {
        root: Utf8PathBuf,
        #[source]
        source: walkdir::Error,
    },
    /// A directory walk yielded an entry whose path is not valid
    /// UTF-8. We carry the lossy form for the error message.
    #[error("Cannot handle non-utf8 path {path_lossy}")]
    NonUtf8Path { path_lossy: String },
    /// The [`FileSet`] pattern has no literal path prefix (e.g.
    /// `**/*.pem`, `*.lua`). Walking such a pattern would have to
    /// descend from `/`, which is almost never what the user wants and
    /// can be catastrophically expensive. Patterns must anchor to a
    /// concrete directory.
    #[error(
        "pattern `{pattern}` has no literal path prefix; \
         anchor it to a directory (e.g. `~/dotfiles/{pattern}`)"
    )]
    NoWalkRoot { pattern: String },
    /// Canonicalizing a path (typically a walk root, or a yielded
    /// symlink target) failed. The path may not exist, may be a
    /// dangling symlink, or the process may lack permission to
    /// traverse the prefix.
    #[error("failed to canonicalize {path}: {source}")]
    CanonicalizeFailure {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Canonicalization yielded a non-UTF-8 path (e.g. the canonical
    /// target lives under a directory with a non-UTF-8 name). We
    /// carry the lossy form for the error message.
    #[error("canonical path is not valid UTF-8: {path_lossy}")]
    NonUtf8CanonicalPath { path_lossy: String },
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
    /// Returns [`VarError::EmptyName`] for empty input, or
    /// [`VarError::NotPosixName`] if the name contains anything outside
    /// `[A-Z_][A-Z0-9_]*`.
    pub fn try_new(s: impl Into<String>) -> Result<Self, VarError> {
        let s = s.into();
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return Err(VarError::EmptyName);
        };
        if !(first.is_ascii_uppercase() || first == '_') {
            return Err(VarError::NotPosixName(s));
        }
        for c in chars {
            if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
                return Err(VarError::NotPosixName(s));
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
    type Err = VarError;
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
    /// Returns [`VarError::EmptyName`] for empty input, or
    /// [`VarError::InvalidLenientName`] if the name contains `=` or NUL.
    pub fn try_new(s: impl Into<String>) -> Result<Self, VarError> {
        let s = s.into();
        if s.is_empty() {
            return Err(VarError::EmptyName);
        }
        if s.contains('=') || s.contains('\0') {
            return Err(VarError::InvalidLenientName(s));
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
    type Err = VarError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// One entry in a `[[vars_lenient]]` array — a non-POSIX variable
/// name paired with its value. The map form (`vars = { ... }`)
/// can't carry the strict/lenient distinction in its keys, hence
/// the separate array form.
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
    /// Returns the [`VarError`] from [`LenientVarName::try_new`] if `name`
    /// is empty or contains `=` / NUL.
    pub fn try_new(name: impl Into<String>, value: VarValue) -> Result<Self, VarError> {
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
/// [`crate::core::loadout::Loadout::all_vars`]). The wire form on
/// [`crate::core::loadout::Loadout`] itself keeps strict and lenient in
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
// ResolvedVar
// =====================================================================

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
    /// Whether the resolved `value` came from the user's environment
    /// (as opposed to a hardcoded literal or a fallback default).
    /// Consumed by the policy gate: a var that doesn't pull user
    /// data isn't a data-leak vector and skips the allow/deny/ignore
    /// check entirely.
    ///
    /// - [`VarValue::Specified`] → `false`
    /// - [`VarValue::Inherit`] (successful lookup) → `true`
    /// - [`VarValue::InheritWithDefault`] with env-hit → `true`
    /// - [`VarValue::InheritWithDefault`] falling back to default → `false`
    carries_user_data: bool,
    /// The original, pre-resolution spec. Preserved so a daemon-side
    /// composer can ship an inherited var to the client *as an
    /// `Inherit`/`InheritWithDefault` spec* (see
    /// `contribution_to_pending`) rather than baking in its own
    /// resolved value — the client must always resolve inherited vars
    /// against the *user's* env. Terminal constructors (already-
    /// resolved values that never get re-shipped) record it as a
    /// [`VarValue::Specified`] of the resolved value.
    spec: VarValue,
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

    /// Whether the resolved value came from the user's environment
    /// (rather than from a hardcoded literal or a fallback default).
    /// The policy gate uses this to skip vars that don't move user
    /// data into the sandbox — nothing to gate.
    #[must_use]
    pub fn carries_user_data(&self) -> bool {
        self.carries_user_data
    }

    /// The original, pre-resolution spec. `contribution_to_pending`
    /// uses this to hand an inherited var back to the client for
    /// user-env resolution instead of shipping the daemon's value.
    #[must_use]
    pub fn spec(&self) -> &VarValue {
        &self.spec
    }

    /// Construct a [`ResolvedVar`] whose value came directly from a
    /// host env lookup, so `carries_user_data` is true. Used by
    /// callers that already ran their own env lookup and need to
    /// hand the result downstream without losing the "user data"
    /// bit — the loadout pre-inherit pass being the canonical
    /// example.
    #[must_use]
    pub fn from_env_value(name: String, value: String) -> Self {
        Self {
            name,
            spec: VarValue::specified(value.clone()),
            value,
            carries_user_data: true,
        }
    }

    /// Construct a [`ResolvedVar`] whose value came from a source-
    /// side literal or a fallback default — no user env data
    /// involved, so `carries_user_data` is false.
    #[must_use]
    pub fn from_literal(name: String, value: String) -> Self {
        Self {
            name,
            spec: VarValue::specified(value.clone()),
            value,
            carries_user_data: false,
        }
    }

    /// Construct a [`ResolvedVar`] with an explicit
    /// `carries_user_data` bit. Sugar over
    /// [`Self::from_env_value`] / [`Self::from_literal`] for
    /// callers that already have the bit computed and want a
    /// single call site.
    #[must_use]
    pub fn from_env_value_or_literal(name: String, value: String, carries_user_data: bool) -> Self {
        Self {
            name,
            spec: VarValue::specified(value.clone()),
            value,
            carries_user_data,
        }
    }

    /// Consume the [`ResolvedVar`] and return `(name, value)`.
    #[must_use]
    pub fn into_parts(self) -> (String, String) {
        (self.name, self.value)
    }

    /// Consume the [`ResolvedVar`] and return every field, including
    /// the `carries_user_data` provenance bit. The wire-form
    /// [`WireResolvedVar`] `From` impl uses this to preserve the bit
    /// across serialization rather than defaulting it on the receiver.
    ///
    /// [`WireResolvedVar`]: crate::wire::primitives::WireResolvedVar
    #[must_use]
    pub fn into_parts_with_provenance(self) -> (String, String, bool) {
        (self.name, self.value, self.carries_user_data)
    }

    /// Resolve a variable against an arbitrary environment-lookup function.
    /// The thread-able shape lets tests pin every branch without touching
    /// the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`VarError::ResolutionFailure`] if `lookup` returns an error
    /// that the variant's semantics surface (every error for
    /// [`VarValue::Inherit`]; only [`std::env::VarError::NotUnicode`] for
    /// [`VarValue::InheritWithDefault`]).
    pub fn resolve_with<F>(name: String, value: VarValue, lookup: F) -> Result<Self, VarError>
    where
        F: FnOnce(&str) -> Result<String, std::env::VarError>,
    {
        // Retain the pre-resolution spec so a daemon-side composer can
        // forward it verbatim for the client to resolve against the
        // user's env (see `contribution_to_pending`).
        let spec = value.clone();
        let (resolved_value, carries_user_data) = match value {
            VarValue::Specified { value } => (value, false),
            VarValue::Inherit => {
                let v = lookup(&name).map_err(|source| VarError::ResolutionFailure {
                    name: name.clone(),
                    source,
                })?;
                (v, true)
            }
            VarValue::InheritWithDefault { default } => match lookup(&name) {
                Ok(value) => (value, true),
                Err(std::env::VarError::NotPresent) => (default, false),
                Err(source @ std::env::VarError::NotUnicode(_)) => {
                    return Err(VarError::ResolutionFailure {
                        name: name.clone(),
                        source,
                    });
                }
            },
        };
        Ok(Self {
            name,
            value: resolved_value,
            carries_user_data,
            spec,
        })
    }

    /// Resolve a variable against the process environment via
    /// [`std::env::var`]. Sugar for [`Self::resolve_with`] with the
    /// default lookup.
    ///
    /// # Errors
    ///
    /// See [`Self::resolve_with`].
    pub fn resolve(name: String, value: VarValue) -> Result<Self, VarError> {
        Self::resolve_with(name, value, |l| std::env::var(l))
    }
}

impl TryFrom<(StrictVarName, VarValue)> for ResolvedVar {
    type Error = VarError;
    fn try_from((name, value): (StrictVarName, VarValue)) -> Result<Self, VarError> {
        Self::resolve(name.into_inner(), value)
    }
}

impl TryFrom<LenientVarEntry> for ResolvedVar {
    type Error = VarError;
    fn try_from(entry: LenientVarEntry) -> Result<Self, Self::Error> {
        let (name, value) = entry.into_parts();
        Self::resolve(name.into_inner(), value)
    }
}

impl From<crate::wire::primitives::WireResolvedVar> for ResolvedVar {
    fn from(v: crate::wire::primitives::WireResolvedVar) -> Self {
        Self {
            name: v.name,
            spec: VarValue::specified(v.value.clone()),
            value: v.value,
            carries_user_data: v.carries_user_data,
        }
    }
}

impl From<crate::wire::primitives::WireVarSpec> for VarValue {
    fn from(spec: crate::wire::primitives::WireVarSpec) -> Self {
        match spec {
            crate::wire::primitives::WireVarSpec::Specified { value } => Self::Specified { value },
            crate::wire::primitives::WireVarSpec::Inherit => Self::Inherit,
            crate::wire::primitives::WireVarSpec::InheritWithDefault { default } => {
                Self::InheritWithDefault { default }
            }
        }
    }
}

impl From<VarValue> for crate::wire::primitives::WireVarSpec {
    fn from(spec: VarValue) -> Self {
        match spec {
            VarValue::Specified { value } => Self::Specified { value },
            VarValue::Inherit => Self::Inherit,
            VarValue::InheritWithDefault { default } => Self::InheritWithDefault { default },
        }
    }
}

// =====================================================================
// FileSet
// =====================================================================

/// A set of host-filesystem files described by a single glob pattern.
///
/// Patterns are parsed at construction time, so malformed input fails at
/// config load with a useful error rather than at apply time. The
/// underlying pattern string is recoverable via [`Self::pattern`].
///
/// # Walk root
///
/// To *enumerate* matching files, the caller walks a directory and
/// filters with the glob. [`Self::walk_root`] returns the longest literal
/// path prefix — the directory the walker should start from. For
/// `~/dotfiles/nvim/**/*.lua` that's `Some("~/dotfiles/nvim")`; for
/// `**/*.pem` it's [`None`] (no literal prefix). The host realm and `~`
/// expansion are the caller's responsibility.
///
/// # Wire format
///
/// A bare string. Lists of patterns live one level up — at the patches
/// array, or in the policy fields — where each entry is its own
/// `FileSet`.
///
/// ```toml
/// allow  = ["~/.config/**", "/etc/xdg/**"]
/// source = "~/dotfiles/nvim/**/*.lua"
/// ```
#[derive(Clone, Debug)]
pub struct FileSet {
    glob: globset::Glob,
    matcher: globset::GlobMatcher,
}

impl FileSet {
    /// Construct a [`FileSet`] from a raw pattern.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::InvalidGlob`] if `pattern` fails to parse.
    pub fn try_new(pattern: impl Into<String>) -> Result<Self, PatchError> {
        let pattern = pattern.into();
        let glob = globset::Glob::new(&pattern)
            .map_err(|source| PatchError::InvalidGlob { pattern, source })?;
        let matcher = glob.compile_matcher();
        Ok(Self { glob, matcher })
    }

    /// The original pattern string (suitable for re-serialization).
    #[must_use]
    pub fn pattern(&self) -> &str {
        self.glob.glob()
    }

    /// The compiled glob, for matching.
    #[must_use]
    pub fn glob(&self) -> &globset::Glob {
        &self.glob
    }

    /// `true` iff this pattern matches `path`.
    #[must_use]
    pub fn is_match(&self, path: impl AsRef<std::path::Path>) -> bool {
        self.matcher.is_match(path.as_ref())
    }

    /// The longest literal path prefix in the pattern — the directory a
    /// walker should start from to enumerate matches.
    ///
    /// Returns [`None`] when the pattern has no literal prefix (e.g.
    /// `**/*.pem`, `*.lua`); callers needing a concrete walk root must
    /// substitute (typically the current directory, or an error).
    /// Otherwise returns the prefix up to — but not including — the slash
    /// before the first metacharacter (`*`, `?`, `[`, `{`) as a
    /// [`HostPath`]. Patterns with no metacharacters return the whole
    /// pattern.
    ///
    /// The returned [`HostPath`] is unexpanded — `~` and `$VAR` are still
    /// raw. Resolving those is the caller's responsibility.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The body contains one `expect`
    /// covering a logically unreachable case — the loop guard
    /// `i < bytes.len()` guarantees the next character exists.
    #[must_use]
    pub fn walk_root(&self) -> Option<HostPath> {
        let pattern = self.pattern();
        let bytes = pattern.as_bytes();
        let mut literal = String::with_capacity(pattern.len());
        let mut last_slash = None;
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            match c {
                b'/' => {
                    last_slash = Some(literal.len());
                    literal.push('/');
                    i += 1;
                }
                b'*' | b'?' | b'{' => {
                    return last_slash
                        .and_then(|s| HostPath::try_new(literal[..s].to_owned()).ok());
                }
                // Single-byte bracket class `[X]` is a literal `X` —
                // this is what `expansion::escape_glob_metas` emits to
                // pass a glob-metacharacter through as a literal path
                // byte. Without this carve-out, `walk_root` would
                // truncate at the inserted `[` and walk a far wider
                // tree than the pattern actually targets.
                //
                // Safe to read `bytes[i+1]` as `char`: `bytes[i+2] == b']'`
                // is ASCII (0x5D); UTF-8 continuation bytes are
                // 0x80..=0xBF and so can't be `]`. So `bytes[i+1]`
                // must itself be at a char boundary and ASCII.
                b'[' if i + 2 < bytes.len() && bytes[i + 2] == b']' => {
                    literal.push(bytes[i + 1] as char);
                    i += 3;
                }
                // Multi-character bracket classes (`[abc]`, `[a-z]`,
                // negations, etc.) are real glob metas — stop here.
                b'[' => {
                    return last_slash
                        .and_then(|s| HostPath::try_new(literal[..s].to_owned()).ok());
                }
                _ => {
                    // Copy the next UTF-8 character whole.
                    let ch_len = pattern[i..]
                        .chars()
                        .next()
                        .expect("non-empty slice has at least one char")
                        .len_utf8();
                    literal.push_str(&pattern[i..i + ch_len]);
                    i += ch_len;
                }
            }
        }
        HostPath::try_new(literal).ok()
    }

    /// Walk the host filesystem under [`Self::walk_root`] and collect
    /// every file whose path matches this pattern.
    ///
    /// Per-entry failures (walk errors, non-UTF-8 paths) are accumulated
    /// into the returned `Vec<PatchError>` rather than aborting the walk —
    /// callers decide whether a partial result is acceptable.
    ///
    /// `~` and `$VAR` are **not** expanded; the walker passes the raw
    /// prefix to the OS. Expand before invoking, or accept that
    /// `~/...` patterns resolve to nothing.
    ///
    /// Patterns with no literal path prefix (e.g. `**/*.pem`, `*.lua`)
    /// would have to start their walk from `/` — virtually never what
    /// the caller wants. Such patterns produce an empty result with a
    /// single [`PatchError::NoWalkRoot`] entry instead of walking the entire
    /// root filesystem.
    #[must_use]
    pub fn resolve(&self, follow_links: bool) -> (Vec<HostPath>, Vec<PatchError>) {
        let Some(root) = self.walk_root() else {
            return (
                Vec::new(),
                vec![PatchError::NoWalkRoot {
                    pattern: self.pattern().to_owned(),
                }],
            );
        };
        let root_path = root.as_utf8_path().to_path_buf();

        let mut paths = Vec::new();
        let mut errors = Vec::new();
        for entry_result in walkdir::WalkDir::new(&root).follow_links(follow_links) {
            match entry_result {
                Ok(entry) if !entry.file_type().is_file() => {}
                Ok(entry) => match Utf8PathBuf::from_path_buf(entry.into_path()) {
                    Ok(p) if self.is_match(&p) => {
                        // walkdir yields concrete on-disk paths under `root`, so this
                        // cannot climb; go through the constructor rather than
                        // forging one, and skip anything that somehow does.
                        if let Ok(hp) = HostPath::try_new(p) {
                            paths.push(hp);
                        }
                    }
                    Ok(_) => {}
                    Err(p) => errors.push(PatchError::NonUtf8Path {
                        path_lossy: p.to_string_lossy().into_owned(),
                    }),
                },
                Err(source) => errors.push(PatchError::WalkFailure {
                    root: root_path.clone(),
                    source,
                }),
            }
        }
        (paths, errors)
    }
}

impl PartialEq for FileSet {
    fn eq(&self, other: &Self) -> bool {
        self.pattern() == other.pattern()
    }
}
impl Eq for FileSet {}

impl std::hash::Hash for FileSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern().hash(state);
    }
}

impl serde::Serialize for FileSet {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.pattern())
    }
}

impl<'de> serde::Deserialize<'de> for FileSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

// =====================================================================
// PatchDest
// =====================================================================

/// A validated patch destination, **relative to the sandbox user's
/// home directory**.
///
/// Every patch lands somewhere under `$HOME` inside the sandbox. A
/// future revision may introduce a separate type for non-home-rooted
/// destinations; until then, `PatchDest` represents only the
/// home-relative case.
///
/// Rejected at construction:
/// - empty paths,
/// - absolute paths (would escape the home anchor),
/// - paths containing `..` components (path-traversal protection — the
///   apply layer also canonicalizes, but rejecting at the config layer
///   gives a config-line-number error and prevents the value from ever
///   existing in memory).
///
/// **Normalized** at construction: `.` components and redundant slashes
/// are dropped. `etc/./foo//bar` becomes `etc/foo/bar`. The original
/// path is not preserved.
///
/// Wraps a [`SandboxRelPath`], so the realm tag is preserved through to
/// the apply layer. No `AsRef<std::path::Path>` is provided on purpose:
/// a destination path cannot be passed to host I/O without going through
/// a [`paths::Translator`] first.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PatchDest(SandboxRelPath);

impl PatchDest {
    /// Construct a `PatchDest` after validation and normalization.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::EmptyDest`] for empty paths, or
    /// [`PatchError::DestTraversal`] for paths containing `..` components.
    pub fn try_new(path: impl Into<Utf8PathBuf>) -> Result<Self, PatchError> {
        let path = path.into();
        if path.as_str().is_empty() {
            return Err(PatchError::EmptyDest);
        }
        // Destinations are semantically relative to the sandbox user's
        // home directory, so a leading `~/` is redundant — the package
        // author who writes `path = "~/.claude"` in their mfile means
        // "place `.claude` under sandbox home", not "place a literal
        // `~` directory there." Strip the prefix once, here, so
        // downstream consumers (tar packing, materialize) don't
        // create paths like `/home/~/.claude`. A bare `~` becomes an
        // empty path and re-hits the empty-dest check below.
        let path: Utf8PathBuf = match path.as_str().strip_prefix("~/") {
            Some(rest) => rest.into(),
            None if path.as_str() == "~" => Utf8PathBuf::new(),
            None => path,
        };
        if path.as_str().is_empty() {
            return Err(PatchError::EmptyDest);
        }
        // Walk components: drop CurDir, fail on ParentDir, keep the
        // rest. RootDir (an absolute path) is allowed through here so
        // SandboxRelPath::try_new can produce its own AbsoluteDestPath
        // error — that gives a more specific message than failing here.
        let mut normalized = Utf8PathBuf::new();
        for component in path.components() {
            match component {
                Utf8Component::CurDir => {}
                Utf8Component::ParentDir => return Err(PatchError::DestTraversal(path)),
                other => normalized.push(other.as_str()),
            }
        }
        Ok(Self(
            SandboxRelPath::try_new(normalized).map_err(PatchError::AbsoluteDestPath)?,
        ))
    }

    /// Borrow the underlying sandbox-home-relative path.
    pub fn as_sandbox_path(&self) -> &SandboxRelPath {
        &self.0
    }
}

impl serde::Serialize for PatchDest {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(ser)
    }
}

impl<'de> serde::Deserialize<'de> for PatchDest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let p = Utf8PathBuf::deserialize(deserializer)?;
        Self::try_new(p).map_err(serde::de::Error::custom)
    }
}

// =====================================================================
// Patch / Patches
// =====================================================================

/// A single patch: a source path expression on the host and the
/// destination inside the sandbox (relative to the sandbox user's home
/// directory) where its content should land.
///
/// `source` is the *raw, unexpanded* path string straight from the wire
/// — it may contain `~/` or `$VAR` / `${VAR}` references. Expansion
/// against the session's gated variables happens later (see
/// [`crate::core::expansion::expand_source`]); attempting to parse it as a
/// glob directly would silently match a literal `$VAR` directory name.
///
/// For single-file sources, `dest` is the destination file path. For
/// multi-file sources (lists, globs, directory copies), `dest` is the
/// destination *directory*. Enforcing this invariant requires expanded
/// paths and is the apply layer's responsibility.
///
/// Patches carry no provenance: which source declared a patch is known
/// to the session-construction layer that combines a [`Loadout`], a
/// project config, and package specs.
///
/// [`Loadout`]: crate::core::loadout::Loadout
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Patch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    source: String,
    dest: PatchDest,
}

impl Patch {
    /// Construct a new patch.
    #[must_use]
    pub fn new(source: impl Into<String>, dest: PatchDest) -> Self {
        Self {
            source: source.into(),
            dest,
            description: None,
        }
    }

    /// The raw, unexpanded source path expression.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The destination path inside the sandbox.
    #[must_use]
    pub fn dest(&self) -> &PatchDest {
        &self.dest
    }
}

/// An ordered collection of [`Patch`] entries — the wire form of a
/// `patches = [...]` array.
///
/// At the wire layer, a single row may carry either one `source` pattern
/// or a list. List-shaped rows fan out into one [`Patch`] per pattern
/// (the `description` and `dest` are shared across the fan-out). After
/// deserialization every [`Patch`] holds exactly one [`FileSet`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct Patches(Vec<Patch>);

impl<'de> serde::Deserialize<'de> for Patches {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Source {
            One(String),
            Many(Vec<String>),
        }
        #[derive(serde::Deserialize)]
        struct Row {
            #[serde(default)]
            description: Option<String>,
            source: Source,
            dest: PatchDest,
        }
        let rows: Vec<Row> = Vec::deserialize(deserializer)?;
        let mut out = Vec::with_capacity(rows.len());
        for Row {
            description,
            source,
            dest,
        } in rows
        {
            match source {
                Source::One(s) => out.push(Patch {
                    description,
                    source: s,
                    dest,
                }),
                Source::Many(ss) => {
                    for s in ss {
                        out.push(Patch {
                            description: description.clone(),
                            source: s,
                            dest: dest.clone(),
                        });
                    }
                }
            }
        }
        Ok(Self(out))
    }
}

impl Patches {
    /// Construct an empty collection. Useful as the start of a builder
    /// chain.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct from a vector of patches.
    #[must_use]
    pub fn new(patches: Vec<Patch>) -> Self {
        Self(patches)
    }

    /// Append a patch in place.
    pub fn push(&mut self, patch: Patch) {
        self.0.push(patch);
    }

    /// Returns `true` if there are no patches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of patches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the patches.
    pub fn iter(&self) -> std::slice::Iter<'_, Patch> {
        self.0.iter()
    }

    /// Append all patches from another collection.
    pub fn extend(&mut self, other: Patches) {
        self.0.extend(other.0);
    }
}

impl FromIterator<Patch> for Patches {
    fn from_iter<I: IntoIterator<Item = Patch>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a Patches {
    type Item = &'a Patch;
    type IntoIter = std::slice::Iter<'a, Patch>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for Patches {
    type Item = Patch;
    type IntoIter = std::vec::IntoIter<Patch>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// =====================================================================
// ResolvedPatch
// =====================================================================

/// A single patch's resolved endpoints: where the file lives on the
/// host, and where it lands inside the sandbox (relative to the
/// sandbox user's home directory).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolvedPatch {
    host_path: HostAbsPath,
    destination: SandboxRelPath,
}

impl ResolvedPatch {
    #[must_use]
    pub fn new(host_path: HostAbsPath, destination: SandboxRelPath) -> Self {
        Self {
            host_path,
            destination,
        }
    }

    /// The absolute host path of the file being copied.
    pub fn host_path(&self) -> &HostAbsPath {
        &self.host_path
    }

    /// The destination the file is copied to, relative to the sandbox
    /// user's home directory.
    pub fn destination(&self) -> &SandboxRelPath {
        &self.destination
    }

    /// Consume the [`ResolvedPatch`] and return `(host_path, destination)`.
    pub fn into_parts(self) -> (HostAbsPath, SandboxRelPath) {
        (self.host_path, self.destination)
    }
}

impl core::fmt::Display for ResolvedPatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} → {}",
            self.host_path.as_str(),
            self.destination.as_str(),
        )
    }
}

impl From<crate::wire::primitives::WireResolvedPatch> for ResolvedPatch {
    fn from(p: crate::wire::primitives::WireResolvedPatch) -> Self {
        Self {
            host_path: p.host_path,
            destination: p.destination,
        }
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
        assert!(matches!(err, VarError::NotPosixName(_)));
    }

    #[test]
    fn lenient_var_name_parses_via_from_str() {
        let n: LenientVarName = "weird-thing".parse().unwrap();
        assert_eq!(n.as_str(), "weird-thing");
        let err = "foo=bar".parse::<LenientVarName>().unwrap_err();
        assert!(matches!(err, VarError::InvalidLenientName(_)));
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
        assert!(matches!(err, VarError::InvalidLenientName(_)));
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
            VarError::ResolutionFailure {
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
            VarError::ResolutionFailure {
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

    // ---- FileSet ----

    #[test]
    fn fileset_from_bare_string() {
        let fs: FileSet = parse(r#"x = "~/.gitconfig""#);
        assert_eq!(fs.pattern(), "~/.gitconfig");
    }

    #[test]
    fn fileset_rejects_invalid_glob() {
        let err = toml::from_str::<Wrap<FileSet>>(r#"x = "[invalid""#).unwrap_err();
        assert!(err.to_string().contains("invalid glob"), "got: {err}");
    }

    #[test]
    fn fileset_round_trips_as_bare_string() {
        let original = FileSet::try_new("./themes/**/*.toml").unwrap();
        let s = toml::to_string(&Wrap {
            x: original.clone(),
        })
        .unwrap();
        assert_eq!(s.trim(), r#"x = "./themes/**/*.toml""#);
        let parsed: FileSet = parse(&s);
        assert_eq!(parsed, original);
    }

    #[test]
    fn fileset_walk_root_extracts_literal_prefix() {
        let cases = [
            ("~/dotfiles/nvim/**/*.lua", Some("~/dotfiles/nvim")),
            ("/etc/xdg/**", Some("/etc/xdg")),
            ("~/.gitconfig", Some("~/.gitconfig")),
            ("**/*.pem", None),
            ("*.lua", None),
            ("src/?oo.rs", Some("src")),
            ("a/b/{c,d}", Some("a/b")),
        ];
        for (pattern, expected) in cases {
            let fs = FileSet::try_new(pattern).unwrap();
            let expected = expected.map(|p| HostPath::try_new(p).unwrap());
            assert_eq!(fs.walk_root(), expected, "pattern: {pattern}");
        }
    }

    /// Regression: `walk_root` must unescape `[X]` single-char bracket
    /// classes. Without this, a substituted value containing a literal
    /// glob metacharacter (e.g. a home directory named `u[1]`) would
    /// get escaped to `[[]1[]]`, and `walk_root` would mistake the
    /// inserted `[` for a real metacharacter and truncate to a
    /// far-too-wide root (often `/home`).
    #[test]
    fn fileset_walk_root_unescapes_single_byte_bracket_class() {
        let cases = [
            // Pattern with escape sequences (no real meta after).
            // `[[]1[]]` is `[`, `1`, `]` — should yield `/home/u[1]/x`.
            ("/home/u[[]1[]]/x", Some("/home/u[1]/x")),
            // Pattern with literal escapes followed by a real glob meta.
            // walk root should be `/home/u[1]/dotfiles`.
            (
                "/home/u[[]1[]]/dotfiles/**/*.lua",
                Some("/home/u[1]/dotfiles"),
            ),
            // Multi-char class is a real meta — truncate at the `[`.
            ("/foo/[abc]/bar", Some("/foo")),
        ];
        for (pattern, expected) in cases {
            let fs = FileSet::try_new(pattern).unwrap();
            let expected = expected.map(|p| HostPath::try_new(p).unwrap());
            assert_eq!(fs.walk_root(), expected, "pattern: {pattern}");
        }
    }

    // ---- PatchDest ----

    #[test]
    fn patchdest_rejects_empty() {
        assert!(matches!(PatchDest::try_new(""), Err(PatchError::EmptyDest)));
    }

    #[test]
    fn patchdest_rejects_traversal() {
        assert!(matches!(
            PatchDest::try_new("foo/../bar"),
            Err(PatchError::DestTraversal(_))
        ));
    }

    #[test]
    fn patchdest_strips_leading_home_tilde() {
        // Package authors write `path = "~/.claude"` in their mfile
        // meaning "map onto sandbox home"; destinations are already
        // home-relative, so the tilde is redundant and must not
        // survive into the tar entry or materialize target (else
        // files land at `/home/~/.claude/...` inside the sandbox).
        let cases = [
            ("~/.claude", ".claude"),
            ("~/foo/bar", "foo/bar"),
            ("~/", ""), // empty after strip → EmptyDest below
        ];
        for (input, expected) in cases {
            if expected.is_empty() {
                assert!(
                    matches!(PatchDest::try_new(input), Err(PatchError::EmptyDest)),
                    "input {input} should reject as empty after tilde strip",
                );
            } else {
                let dest = PatchDest::try_new(input).expect(input);
                assert_eq!(dest.as_sandbox_path().as_str(), expected, "input: {input}");
            }
        }
        // Bare `~` is also nonsensical as a destination — home root
        // itself isn't a file target — so it rejects as empty too.
        assert!(matches!(
            PatchDest::try_new("~"),
            Err(PatchError::EmptyDest)
        ));
    }

    #[test]
    fn patchdest_drops_curdir_and_redundant_slashes() {
        let cases = [
            ("etc/./foo", "etc/foo"),
            ("etc//foo", "etc/foo"),
            ("./etc/foo", "etc/foo"),
            ("etc/foo/.", "etc/foo"),
            ("etc/./foo/./bar", "etc/foo/bar"),
            ("etc//.//foo", "etc/foo"),
        ];
        for (input, expected) in cases {
            let dest = PatchDest::try_new(input).expect(input);
            assert_eq!(dest.as_sandbox_path().as_str(), expected, "input: {input}");
        }
    }

    #[test]
    fn patchdest_traversal_check_runs_after_normalization_walk() {
        // `etc/.././foo` simplifies to `foo` superficially, but the
        // `..` is present in the *components*. PatchDest::try_new
        // walks components and rejects on the first `..` regardless
        // of what later normalization would produce.
        assert!(matches!(
            PatchDest::try_new("etc/.././foo"),
            Err(PatchError::DestTraversal(_))
        ));
    }

    #[test]
    fn patch_deserialize_rejects_bad_dest() {
        let err = toml::from_str::<Wrap<Patch>>(r#"x = { dest = "foo/../bar", source = "a" }"#)
            .unwrap_err();
        assert!(err.to_string().contains(".."), "got: {err}");
    }

    // ---- Patch / Patches ----

    #[test]
    fn patch_with_string_source() {
        let p: Patch = parse(r#"x = { dest = "etc/foo.conf", source = "./foo.conf" }"#);
        assert_eq!(p.dest().as_sandbox_path().as_str(), "etc/foo.conf");
        assert_eq!(p.source(), "./foo.conf");
    }

    #[test]
    fn patches_deserialize_from_array() {
        let src = r#"
            x = [
                { dest = "a", source = "a" },
                { dest = "b", source = "b" },
            ]
        "#;
        let ps: Patches = parse(src);
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn patches_fan_out_multi_pattern_source() {
        let src = r#"
            x = [
                { dest = "wallpapers", source = ["a/*.jpg", "a/*.png"] },
            ]
        "#;
        let ps: Patches = parse(src);
        // One row, two patterns → two patches with the same dest.
        assert_eq!(ps.len(), 2);
        let dests: Vec<_> = ps
            .iter()
            .map(|p| p.dest().as_sandbox_path().as_str().to_owned())
            .collect();
        assert_eq!(dests, ["wallpapers", "wallpapers"]);
        let sources: Vec<_> = ps.iter().map(|p| p.source().to_owned()).collect();
        assert_eq!(sources, ["a/*.jpg", "a/*.png"]);
    }

    #[test]
    fn patches_fan_out_propagates_description() {
        let src = r#"
            x = [
                { description = "lovely-fonts", dest = "fonts", source = ["a.ttf", "b.ttf"] },
            ]
        "#;
        let ps: Patches = parse(src);
        assert_eq!(ps.len(), 2);
        // `description` is private; the Debug output reveals it. Both
        // fan-out entries must carry the same description as the source row.
        let dbg = format!("{ps:?}");
        assert_eq!(dbg.matches("lovely-fonts").count(), 2);
    }

    // ---- Patches builders ----

    #[test]
    fn patches_builder_surfaces_compose() {
        let make = |s: &str| Patch::new(s, PatchDest::try_new(s).unwrap());

        let collected: Patches = ["a", "b"].into_iter().map(make).collect();
        let mut built = Patches::empty();
        built.push(make("a"));
        built.push(make("b"));
        assert_eq!(collected, built);
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn patches_extend_appends_other_collection() {
        let make = |s: &str| Patch::new(s, PatchDest::try_new(s).unwrap());
        let mut ps: Patches = ["a", "b"].into_iter().map(make).collect();
        let extra: Patches = ["c", "d"].into_iter().map(make).collect();
        ps.extend(extra);
        let dests: Vec<_> = ps
            .iter()
            .map(|p| p.dest().as_sandbox_path().as_str().to_owned())
            .collect();
        assert_eq!(dests, ["a", "b", "c", "d"]);
    }
}
