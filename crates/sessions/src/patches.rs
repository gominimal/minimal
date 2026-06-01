//! Patches: descriptions of files brought into a session and the policy
//! controlling which non-user patches are honored.
//!
//! # Sources
//!
//! Patches can be declared by three kinds of source — a user [`Loadout`],
//! a project's `minimal.toml`, and individual package specs — and each
//! source contributes its patches to the session. The primitives here
//! are origin-free: provenance is known to the session-construction
//! layer that combines the three sources, and that layer is where the
//! [`PatchPolicy`] gate applies (see [`PatchPolicy`] for the rules).
//!
//! [`Loadout`]: crate::loadout::Loadout
//!
//! # The `FileSet` primitive
//!
//! [`FileSet`] is the description of "which files" — reused for patch
//! sources, allowlists, denylists, and ignore lists. The wire form accepts
//! three shapes (bare string, list, table); see its docs.
//!
//! Path expansion (`~`, `$VAR`) and canonicalization are **not** performed
//! by this module — `FileSet` stores patterns as written. Callers must
//! resolve them at config-load time before using them for policy checks,
//! since comparing unresolved paths is a path-traversal hazard.
//! This is necessary because which `$VAR` can be used are subject to
//! a separate policy.
//!
//! # Example user config
//!
//! ```toml
//! # User-origin patches — applied unconditionally outside hermetic builds.
//! # Only `ignore` from `[patch_policy]` filters these; `allow`/`deny` are
//! # bypassed.
//! patches = [
//!     { dest = "~/.gitconfig",                       source = "~/dotfiles/gitconfig" },
//!     { dest = "~/.config/alacritty/alacritty.toml", source = "~/dotfiles/alacritty.toml" },
//!     { dest = "~/.config/nvim/",                    source = { base = "~/dotfiles/nvim", patterns = ["**/*"] } },
//!
//!     # Multi-glob to one dest:
//!     { dest = "~/Pictures/wallpapers/",             source = ["~/dotfiles/wallpapers/*.jpg",
//!                                                              "~/dotfiles/wallpapers/*.png"] },
//! ]
//!
//! # Policy for non-user patches (project and package origins).
//! # `ignore` here also applies to user-origin patches above.
//! [patch_policy]
//! allow  = ["~/.config/**", "~/.local/share/applications/**", "/etc/xdg/**"]
//! deny   = ["~/.ssh/**", "~/.aws/**", "**/id_rsa*", "**/*.pem"]
//! ignore = ["**/.DS_Store", "**/*.bak", "**/*.swp"]
//! ```

use camino::{Utf8Component, Utf8PathBuf};
use core::fmt;
use paths::{HostPath, SandboxPath};

/// Errors produced when constructing patch types.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// A pattern string failed to parse as a glob.
    InvalidGlob {
        pattern: String,
        source: globset::Error,
    },
    /// A `FileSet` had an empty `base` (e.g. `base = ""`).
    EmptyBase,
    /// A patch destination was empty.
    EmptyDest,
    /// A patch destination contained a `..` component, which is rejected
    /// before path canonicalization to avoid traversal attacks.
    DestTraversal(Utf8PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGlob { pattern, source } => {
                write!(f, "invalid glob pattern `{pattern}`: {source}")
            }
            Self::EmptyBase => f.write_str("`base` must not be the empty string"),
            Self::EmptyDest => f.write_str("patch destination must not be empty"),
            Self::DestTraversal(p) => write!(
                f,
                "patch destination `{p}` must not contain `..` components",
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidGlob { source, .. } => Some(source),
            _ => None,
        }
    }
}

// =====================================================================
// FileSet
// =====================================================================

/// A description of a set of files on the *host* filesystem: an optional
/// base directory plus glob patterns interpreted relative to it.
///
/// Patterns are parsed as globs at construction time, so malformed patterns
/// fail at config load with a useful error rather than at apply time. Use
/// [`FileSet::raw_patterns`] to recover the original pattern strings (e.g.
/// for re-serialization).
///
/// Absolute or `~`-prefixed patterns are valid; the [`base`](Self::base)
/// field is meaningful only for relative patterns. `~`-prefixed bases
/// classify as [`HostPath::Rel`] — the apply layer is responsible for
/// expansion. The apply layer should follow `Utf8PathBuf::join` semantics
/// when combining a base with a pattern (an absolute right-hand side
/// replaces the left).
///
/// # Wire format
///
/// `FileSet` accepts three forms when deserialized — pick whichever is least
/// noisy at the call site:
///
/// ```toml
/// allow  = "~/.config/**"                                           # bare string
/// deny   = ["~/.ssh/**", "**/id_rsa*"]                              # list
/// source = { base = "~/dotfiles/nvim", patterns = ["**/*"] }        # full table
/// ```
#[derive(Clone, Debug)]
pub struct FileSet {
    base: Option<HostPath>,
    patterns: Vec<String>,
    compiled: Vec<globset::Glob>,
}

impl FileSet {
    /// Construct a [`FileSet`] from raw patterns and an optional base.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidGlob`] if any pattern fails to parse, or
    /// [`Error::EmptyBase`] if `base` is `Some` but empty.
    pub fn try_new<I, S>(base: Option<HostPath>, patterns: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Some(b) = &base
            && b.as_str().is_empty()
        {
            return Err(Error::EmptyBase);
        }
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
        Ok(Self {
            base,
            patterns: raw,
            compiled,
        })
    }

    /// Construct an empty `FileSet`. Useful as a `Default` for policy fields
    /// where "matches nothing" is a meaningful default.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            base: None,
            patterns: Vec::new(),
            compiled: Vec::new(),
        }
    }

    /// Set the base directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyBase`] if `base`'s underlying path is empty.
    pub fn try_with_base(self, base: HostPath) -> Result<Self, Error> {
        if base.as_str().is_empty() {
            return Err(Error::EmptyBase);
        }
        Ok(Self {
            base: Some(base),
            ..self
        })
    }

    /// Append a single pattern.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidGlob`] if the pattern fails to parse.
    pub fn try_with_pattern(self, pattern: impl Into<String>) -> Result<Self, Error> {
        let pattern = pattern.into();
        let glob = globset::Glob::new(&pattern).map_err(|source| Error::InvalidGlob {
            pattern: pattern.clone(),
            source,
        })?;
        let mut new = self;
        new.patterns.push(pattern);
        new.compiled.push(glob);
        Ok(new)
    }

    /// The base directory for relative patterns, if set.
    #[must_use]
    pub fn base(&self) -> Option<&HostPath> {
        self.base.as_ref()
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

    /// Returns `true` if the set contains no patterns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

impl Default for FileSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl PartialEq for FileSet {
    fn eq(&self, other: &Self) -> bool {
        // `compiled` is derived from `patterns`, so equality on the raw inputs
        // implies equality of the compiled forms.
        self.base == other.base && self.patterns == other.patterns
    }
}
impl Eq for FileSet {}

impl std::hash::Hash for FileSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.base.hash(state);
        self.patterns.hash(state);
    }
}

impl serde::Serialize for FileSet {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let len = 1 + usize::from(self.base.is_some());
        let mut st = ser.serialize_struct("FileSet", len)?;
        if let Some(b) = &self.base {
            st.serialize_field("base", b)?;
        }
        st.serialize_field("patterns", &self.patterns)?;
        st.end()
    }
}

impl<'de> serde::Deserialize<'de> for FileSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Full {
                #[serde(default)]
                base: Option<HostPath>,
                patterns: Vec<String>,
            },
            Many(Vec<String>),
            One(String),
        }
        let (base, patterns) = match Repr::deserialize(deserializer)? {
            Repr::Full { base, patterns } => (base, patterns),
            Repr::Many(p) => (None, p),
            Repr::One(p) => (None, vec![p]),
        };
        Self::try_new(base, patterns).map_err(serde::de::Error::custom)
    }
}

// =====================================================================
// PatchDest
// =====================================================================

/// A validated patch destination — a path inside the *sandbox*, where the
/// patch's content will land.
///
/// Rejected at construction:
/// - empty paths,
/// - paths containing `..` components (path-traversal protection — the
///   apply layer also canonicalizes, but rejecting at the config layer
///   gives a config-line-number error and prevents the value from ever
///   existing in memory).
///
/// Wraps a [`SandboxPath`], so the realm tag is preserved through to the
/// apply layer. No `AsRef<std::path::Path>` is provided on purpose: a
/// destination path cannot be passed to host I/O without going through a
/// [`paths::Translator`] first.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PatchDest(SandboxPath);

impl PatchDest {
    /// Construct a `PatchDest` after validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyDest`] for empty paths, or
    /// [`Error::DestTraversal`] for paths containing `..` components.
    pub fn try_new(path: impl Into<Utf8PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        if path.as_str().is_empty() {
            return Err(Error::EmptyDest);
        }
        if path
            .components()
            .any(|c| matches!(c, Utf8Component::ParentDir))
        {
            return Err(Error::DestTraversal(path));
        }
        Ok(Self(SandboxPath::new(path)))
    }

    /// Borrow the underlying sandbox path.
    #[must_use]
    pub fn as_sandbox_path(&self) -> &SandboxPath {
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

/// A single patch: a source fileset and the destination it should land
/// at inside the sandbox.
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
/// [`Loadout`]: crate::loadout::Loadout
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Patch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    source: FileSet,
    dest: PatchDest,
}

impl Patch {
    /// Construct a new patch.
    #[must_use]
    pub fn new(source: FileSet, dest: PatchDest) -> Self {
        Self {
            source,
            dest,
            description: None,
        }
    }

    /// The source fileset.
    #[must_use]
    pub fn source(&self) -> &FileSet {
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Patches(Vec<Patch>);

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

    /// Append a patch and return the modified collection (builder style).
    #[must_use]
    pub fn with_patch(self, patch: Patch) -> Self {
        let mut new = self;
        new.0.push(patch);
        new
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

// =====================================================================
// PatchPolicy
// =====================================================================

/// Policy gating which patches are honored.
///
/// Applied at the session-construction layer based on a patch's source:
///
/// - **User-origin patches** (from a [`Loadout`]): only
///   [`ignore`](Self::ignore) applies. `allow` and `deny` are bypassed —
///   the user is the policy for their own declarations.
/// - **Project- and Package-origin patches**: all three fields apply.
///   A patch is honored iff its destination matches `allow`, does not
///   match `deny`, and does not match `ignore`. Patches matching only
///   `ignore` are silently dropped; matching `deny` is an error/prompt;
///   matching neither `allow` nor `ignore` triggers a permission prompt.
///
/// Precedence within the policy: `ignore` first (silent), then `deny`
/// (reject), then `allow` (permit). Anything else prompts.
///
/// [`Loadout`]: crate::loadout::Loadout
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatchPolicy {
    #[serde(default, skip_serializing_if = "FileSet::is_empty")]
    allow: FileSet,
    #[serde(default, skip_serializing_if = "FileSet::is_empty")]
    deny: FileSet,
    #[serde(default, skip_serializing_if = "FileSet::is_empty")]
    ignore: FileSet,
}

impl PatchPolicy {
    /// Construct an empty policy. Build it up with [`Self::with_allow`],
    /// [`Self::with_deny`], and [`Self::with_ignore`] (or their
    /// pattern-accepting `try_with_*` variants).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace the `allow` set.
    #[must_use]
    pub fn with_allow(self, allow: FileSet) -> Self {
        Self { allow, ..self }
    }

    /// Replace the `deny` set.
    #[must_use]
    pub fn with_deny(self, deny: FileSet) -> Self {
        Self { deny, ..self }
    }

    /// Replace the `ignore` set.
    #[must_use]
    pub fn with_ignore(self, ignore: FileSet) -> Self {
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
        Ok(self.with_allow(FileSet::try_new(None, patterns)?))
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
        Ok(self.with_deny(FileSet::try_new(None, patterns)?))
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
        Ok(self.with_ignore(FileSet::try_new(None, patterns)?))
    }

    /// Paths non-user patches **may** target. Does not apply to
    /// user-origin patches.
    #[must_use]
    pub fn allow(&self) -> &FileSet {
        &self.allow
    }

    /// Paths non-user patches **must not** target. Does not apply to
    /// user-origin patches.
    #[must_use]
    pub fn deny(&self) -> &FileSet {
        &self.deny
    }

    /// Paths to silently drop without prompting. **Applies to every
    /// origin, user-origin included.**
    #[must_use]
    pub fn ignore(&self) -> &FileSet {
        &self.ignore
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

    // ---- FileSet ----

    #[test]
    fn fileset_from_bare_string() {
        let fs: FileSet = parse(r#"x = "~/.gitconfig""#);
        assert_eq!(fs.raw_patterns(), &["~/.gitconfig"]);
        assert!(fs.base().is_none());
        assert_eq!(fs.globs().len(), 1);
    }

    #[test]
    fn fileset_from_list() {
        let fs: FileSet = parse(r#"x = ["**/*.jpg", "**/*.png"]"#);
        assert_eq!(fs.raw_patterns(), &["**/*.jpg", "**/*.png"]);
        assert_eq!(fs.globs().len(), 2);
    }

    #[test]
    fn fileset_from_full_table() {
        let fs: FileSet = parse(r#"x = { base = "./assets", patterns = ["**/*.jpg"] }"#);
        assert_eq!(fs.base().map(HostPath::as_str), Some("./assets"));
        assert_eq!(fs.raw_patterns(), &["**/*.jpg"]);
    }

    #[test]
    fn fileset_rejects_invalid_glob() {
        let err = toml::from_str::<Wrap<FileSet>>(r#"x = "[invalid""#).unwrap_err();
        assert!(err.to_string().contains("invalid glob"), "got: {err}");
    }

    #[test]
    fn fileset_rejects_empty_base() {
        let err =
            toml::from_str::<Wrap<FileSet>>(r#"x = { base = "", patterns = ["a"] }"#).unwrap_err();
        assert!(err.to_string().contains("base"), "got: {err}");
    }

    #[test]
    fn fileset_round_trip() {
        let original =
            FileSet::try_new(Some(HostPath::new("./themes")), ["**/*", "**/*.toml"]).unwrap();
        let s = toml::to_string(&Wrap {
            x: original.clone(),
        })
        .unwrap();
        let parsed: FileSet = parse(&s);
        assert_eq!(parsed, original);
    }

    #[test]
    fn fileset_serializes_without_base_when_none() {
        let fs = FileSet::try_new(None, ["a"]).unwrap();
        let s = toml::to_string(&Wrap { x: fs }).unwrap();
        assert!(s.contains("patterns"));
        assert!(!s.contains("base"));
    }

    // ---- PatchDest ----

    #[test]
    fn patchdest_rejects_empty() {
        assert!(matches!(PatchDest::try_new(""), Err(Error::EmptyDest)));
    }

    #[test]
    fn patchdest_rejects_traversal() {
        assert!(matches!(
            PatchDest::try_new("foo/../bar"),
            Err(Error::DestTraversal(_))
        ));
    }

    #[test]
    fn patchdest_classifies_absolute_and_home_paths() {
        let abs = PatchDest::try_new("/etc/foo").unwrap();
        assert!(abs.as_sandbox_path().is_absolute());
        // Tilde-prefixed paths classify as Rel — apply layer expands them.
        let home = PatchDest::try_new("~/.gitconfig").unwrap();
        assert!(!home.as_sandbox_path().is_absolute());
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
        let p: Patch = parse(r#"x = { dest = "/etc/foo.conf", source = "./foo.conf" }"#);
        assert_eq!(p.dest().as_sandbox_path().as_str(), "/etc/foo.conf");
        assert_eq!(p.source().raw_patterns(), &["./foo.conf"]);
    }

    #[test]
    fn patches_deserialize_from_array() {
        let src = r#"
            x = [
                { dest = "/a", source = "a" },
                { dest = "/b", source = ["b1", "b2"] },
            ]
        "#;
        let ps: Patches = parse(src);
        assert_eq!(ps.len(), 2);
    }

    // ---- PatchPolicy ----

    #[test]
    fn patch_policy_full_example() {
        let src = r#"
            allow = ["~/.config/**", "/etc/xdg/**"]
            deny = ["~/.ssh/**", "**/*.pem"]
            ignore = ["**/.DS_Store"]
        "#;
        let policy: PatchPolicy = toml::from_str(src).unwrap();
        assert_eq!(policy.allow().raw_patterns().len(), 2);
        assert_eq!(policy.deny().raw_patterns().len(), 2);
        assert_eq!(policy.ignore().raw_patterns().len(), 1);
    }

    #[test]
    fn patch_policy_defaults_when_omitted() {
        let policy: PatchPolicy = toml::from_str("").unwrap();
        assert!(policy.allow().is_empty());
        assert!(policy.deny().is_empty());
        assert!(policy.ignore().is_empty());
    }

    #[test]
    fn patch_policy_builder_methods() {
        let p = PatchPolicy::empty()
            .try_with_allow(["~/.config/**"])
            .unwrap()
            .try_with_deny(["~/.ssh/**", "**/*.pem"])
            .unwrap()
            .try_with_ignore(["**/.DS_Store"])
            .unwrap();
        assert_eq!(p.allow().raw_patterns(), &["~/.config/**"]);
        assert_eq!(p.deny().raw_patterns(), &["~/.ssh/**", "**/*.pem"]);
        assert_eq!(p.ignore().raw_patterns(), &["**/.DS_Store"]);
    }

    #[test]
    fn patch_policy_try_with_allow_propagates_invalid_glob() {
        let err = PatchPolicy::empty().try_with_allow(["[bad"]).unwrap_err();
        assert!(matches!(err, Error::InvalidGlob { .. }), "got: {err:?}");
    }

    // ---- FileSet builders ----

    #[test]
    fn fileset_try_with_base_and_pattern_chain() {
        let fs = FileSet::empty()
            .try_with_base(HostPath::new("./themes"))
            .unwrap()
            .try_with_pattern("**/*")
            .unwrap()
            .try_with_pattern("**/*.toml")
            .unwrap();
        assert_eq!(fs.base().map(HostPath::as_str), Some("./themes"));
        assert_eq!(fs.raw_patterns(), &["**/*", "**/*.toml"]);
    }

    #[test]
    fn fileset_try_with_base_rejects_empty() {
        let err = FileSet::empty()
            .try_with_base(HostPath::new(""))
            .unwrap_err();
        assert!(matches!(err, Error::EmptyBase), "got: {err:?}");
    }

    #[test]
    fn fileset_try_with_pattern_propagates_invalid_glob() {
        let err = FileSet::empty().try_with_pattern("[bad").unwrap_err();
        assert!(matches!(err, Error::InvalidGlob { .. }), "got: {err:?}");
    }

    // ---- Patches builders ----

    #[test]
    fn patches_builder_surfaces_compose() {
        let make = |s: &str| {
            Patch::new(
                FileSet::try_new(None, [s]).unwrap(),
                PatchDest::try_new(format!("/{s}")).unwrap(),
            )
        };

        // collect / with_patch / push all feed the same internal Vec.
        let collected: Patches = ["a", "b"].into_iter().map(make).collect();
        let mut built = Patches::empty().with_patch(make("a"));
        built.push(make("b"));
        assert_eq!(collected, built);
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn patches_extend_appends_other_collection() {
        let make = |s: &str| {
            Patch::new(
                FileSet::try_new(None, [s]).unwrap(),
                PatchDest::try_new(format!("/{s}")).unwrap(),
            )
        };
        let mut ps: Patches = ["a", "b"].into_iter().map(make).collect();
        let extra: Patches = ["c", "d"].into_iter().map(make).collect();
        ps.extend(extra);
        let dests: Vec<_> = ps
            .iter()
            .map(|p| p.dest().as_sandbox_path().as_str().to_owned())
            .collect();
        assert_eq!(dests, ["/a", "/b", "/c", "/d"]);
    }

    #[test]
    fn fileset_accepts_absolute_base() {
        let fs = FileSet::try_new(Some(HostPath::new("/etc/xdg")), ["**/*.conf"]).unwrap();
        assert_eq!(fs.base().map(HostPath::as_str), Some("/etc/xdg"));
    }
}
