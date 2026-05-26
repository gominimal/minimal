//! Patches: descriptions of files brought into a session, the provenance of
//! each patch, and the policy controlling which non-user patches are honored.
//!
//! # Sources of patches
//!
//! Patches enter the session from three distinct origins (see [`PatchOrigin`]):
//!
//! - **User** — the user's personal config. Implicit trust: only [`PatchPolicy::ignore`]
//!   applies; `allow` and `deny` are bypassed (the user *is* the policy).
//! - **Project** — the shared `minimal.toml` in the project. Subject to the
//!   full policy (`allow`, `deny`, `ignore`) — a project config can't
//!   silently read from your `~/.ssh`.
//! - **Package** — declared by an installed package's spec. Subject to the
//!   full policy. Carries the package name so prompts/errors can attribute
//!   the request.
//!
//! # Wire form vs domain form
//!
//! TOML files describe patches without origin information — the *loader*
//! attaches the origin based on which file the declaration came from. The
//! split is reflected in the types:
//!
//! - [`PatchDecl`] / [`PatchDecls`] — wire form. Deserialized from TOML.
//! - [`Patch`] / [`Patches`] — domain form. Built from a [`PatchDecls`] plus
//!   a [`PatchOrigin`] via [`PatchDecls::promote`].
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

use crate::paths::{HostPath, SandboxPath};
use camino::{Utf8Component, Utf8PathBuf};
use core::fmt;

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
// PatchOrigin
// =====================================================================

/// Where a patch came from. Determines how [`PatchPolicy`] applies:
///
/// | Origin    | `allow` / `deny` | `ignore` |
/// |-----------|------------------|----------|
/// | `User`    | bypassed         | applies  |
/// | `Project` | applies          | applies  |
/// | `Package` | applies          | applies  |
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PatchOrigin {
    /// From the user's personal config.
    User,
    /// From the shared project config (`minimal.toml`).
    Project,
    /// Declared by an installed package's spec.
    Package {
        /// Name (or identifier) of the package that declared the patch.
        /// Used in permission prompts and error messages.
        package: String,
    },
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
/// [`crate::paths::Translator`] first.
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
// PatchDecl / PatchDecls — wire form
// =====================================================================

/// A patch as declared in a config file, **before** origin is attached.
///
/// This is the form that comes out of deserializing TOML — the file itself
/// doesn't say where it came from, so origin is supplied by the loader via
/// [`Self::promote`] (or in bulk via [`PatchDecls::promote`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PatchDecl {
    source: FileSet,
    dest: PatchDest,
}

impl PatchDecl {
    /// Construct a declaration without origin.
    #[must_use]
    pub fn new(source: FileSet, dest: PatchDest) -> Self {
        Self { source, dest }
    }

    /// The source fileset.
    #[must_use]
    pub fn source(&self) -> &FileSet {
        &self.source
    }

    /// The destination path.
    #[must_use]
    pub fn dest(&self) -> &PatchDest {
        &self.dest
    }

    /// Attach an origin and produce a fully-typed [`Patch`].
    #[must_use]
    pub fn promote(self, origin: PatchOrigin) -> Patch {
        Patch {
            source: self.source,
            dest: self.dest,
            origin,
        }
    }
}

/// An ordered collection of [`PatchDecl`] entries — the wire form of a
/// `patches = [...]` array.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct PatchDecls(Vec<PatchDecl>);

impl PatchDecls {
    /// Construct from a vector of declarations.
    #[must_use]
    pub fn new(decls: Vec<PatchDecl>) -> Self {
        Self(decls)
    }

    /// Returns `true` if there are no declarations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of declarations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the declarations.
    pub fn iter(&self) -> std::slice::Iter<'_, PatchDecl> {
        self.0.iter()
    }

    /// Promote every declaration to a [`Patch`] with the given origin.
    #[must_use]
    pub fn promote(self, origin: &PatchOrigin) -> Patches {
        Patches(
            self.0
                .into_iter()
                .map(|d| d.promote(origin.clone()))
                .collect(),
        )
    }
}

impl<'a> IntoIterator for &'a PatchDecls {
    type Item = &'a PatchDecl;
    type IntoIter = std::slice::Iter<'a, PatchDecl>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

// =====================================================================
// Patch / Patches — domain form
// =====================================================================

/// A single patch entry with its origin attached.
///
/// For single-file sources, `dest` is the destination file path. For
/// multi-file sources (lists, globs, directory copies), `dest` is the
/// destination *directory*. Enforcing this invariant requires expanded paths
/// and is the apply layer's responsibility.
///
/// Construct via [`Patch::new`] or by promoting a [`PatchDecl`] with
/// [`PatchDecl::promote`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Patch {
    source: FileSet,
    dest: PatchDest,
    origin: PatchOrigin,
}

impl Patch {
    /// Construct a new patch.
    #[must_use]
    pub fn new(source: FileSet, dest: PatchDest, origin: PatchOrigin) -> Self {
        Self {
            source,
            dest,
            origin,
        }
    }

    /// The source fileset.
    #[must_use]
    pub fn source(&self) -> &FileSet {
        &self.source
    }

    /// The destination path.
    #[must_use]
    pub fn dest(&self) -> &PatchDest {
        &self.dest
    }

    /// Where the patch came from.
    #[must_use]
    pub fn origin(&self) -> &PatchOrigin {
        &self.origin
    }
}

/// An ordered collection of [`Patch`] entries.
///
/// Not directly deserializable — patches require an origin, which the wire
/// format doesn't carry. Build from a [`PatchDecls`] via
/// [`PatchDecls::promote`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Patches(Vec<Patch>);

impl Patches {
    /// Construct from a vector of patches.
    #[must_use]
    pub fn new(patches: Vec<Patch>) -> Self {
        Self(patches)
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
/// Applied to patches based on their [`PatchOrigin`]:
///
/// - **User-origin patches**: only [`ignore`](Self::ignore) applies.
///   `allow` and `deny` are bypassed — the user is the policy for their own
///   declarations.
/// - **Project- and Package-origin patches**: all three fields apply.
///   A patch is honored iff its destination matches `allow`, does not match
///   `deny`, and does not match `ignore`. Patches matching only `ignore`
///   are silently dropped; matching `deny` is an error/prompt; matching
///   neither `allow` nor `ignore` triggers a permission prompt.
///
/// Precedence within the policy: `ignore` first (silent), then `deny`
/// (reject), then `allow` (permit). Anything else prompts.
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
    /// Construct a policy from its three filesets.
    #[must_use]
    pub fn new(allow: FileSet, deny: FileSet, ignore: FileSet) -> Self {
        Self {
            allow,
            deny,
            ignore,
        }
    }

    /// Paths non-user patches **may** target. Does not apply to
    /// [`PatchOrigin::User`].
    #[must_use]
    pub fn allow(&self) -> &FileSet {
        &self.allow
    }

    /// Paths non-user patches **must not** target. Does not apply to
    /// [`PatchOrigin::User`].
    #[must_use]
    pub fn deny(&self) -> &FileSet {
        &self.deny
    }

    /// Paths to silently drop without prompting. **Applies to every origin
    /// including [`PatchOrigin::User`].**
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
    fn patchdest_accepts_absolute_and_home_paths() {
        assert!(PatchDest::try_new("/etc/foo").is_ok());
        assert!(PatchDest::try_new("~/.gitconfig").is_ok());
    }

    #[test]
    fn patchdest_classifies_absolute_into_sandbox_abs_variant() {
        let dest = PatchDest::try_new("/etc/foo").unwrap();
        assert!(dest.as_sandbox_path().is_absolute());
        // Tilde-prefixed paths classify as Rel — apply layer expands them.
        let home = PatchDest::try_new("~/.gitconfig").unwrap();
        assert!(!home.as_sandbox_path().is_absolute());
    }

    #[test]
    fn patchdecl_deserialize_rejects_bad_dest() {
        let err = toml::from_str::<Wrap<PatchDecl>>(r#"x = { dest = "foo/../bar", source = "a" }"#)
            .unwrap_err();
        assert!(err.to_string().contains(".."), "got: {err}");
    }

    // ---- PatchDecl / PatchDecls / promote ----

    #[test]
    fn patchdecl_with_string_source() {
        let d: PatchDecl = parse(r#"x = { dest = "/etc/foo.conf", source = "./foo.conf" }"#);
        assert_eq!(d.dest().as_sandbox_path().as_str(), "/etc/foo.conf");
        assert_eq!(d.source().raw_patterns(), &["./foo.conf"]);
    }

    #[test]
    fn patchdecls_deserialize_from_array() {
        let src = r#"
            x = [
                { dest = "/a", source = "a" },
                { dest = "/b", source = ["b1", "b2"] },
            ]
        "#;
        let ds: PatchDecls = parse(src);
        assert_eq!(ds.len(), 2);
    }

    #[test]
    fn promote_attaches_origin_to_every_patch() {
        let src = r#"
            x = [
                { dest = "/a", source = "a" },
                { dest = "/b", source = "b" },
            ]
        "#;
        let decls: PatchDecls = parse(src);
        let patches = decls.promote(&PatchOrigin::Project);
        assert_eq!(patches.len(), 2);
        for p in &patches {
            assert_eq!(p.origin(), &PatchOrigin::Project);
        }
    }

    #[test]
    fn promote_with_package_origin_preserves_package_name() {
        let decl = PatchDecl::new(
            FileSet::try_new(None, ["a"]).unwrap(),
            PatchDest::try_new("/a").unwrap(),
        );
        let patch = decl.promote(PatchOrigin::Package {
            package: "git".into(),
        });
        match patch.origin() {
            PatchOrigin::Package { package } => assert_eq!(package, "git"),
            other => panic!("expected Package origin, got {other:?}"),
        }
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
}
