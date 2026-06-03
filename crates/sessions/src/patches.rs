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
//! [`FileSet`] is the description of "which files" — a single glob pattern,
//! reused for patch sources, allowlists, denylists, and ignore lists. The
//! wire form is always a bare string; lists of patterns live one level
//! up (at the patches array or in policy fields).
//!
//! Path expansion is split by responsibility:
//!
//! - **`FileSet` itself** stores patterns as written. No expansion at
//!   construction or matching time.
//! - **The session resolver** ([`composable::Composer::resolve`](crate::composable::Composer::resolve))
//!   expands leading `~` in patch *source* patterns and in
//!   [`PatchPolicy`] patterns at the start of resolution, against
//!   `dirs::home_dir` (or a `Composer::with_home(...)` override).
//!   Patterns retain their `~` form in returned policies for
//!   round-trippability.
//! - **[`PatchDest`] needs no expansion.** Every destination is
//!   implicitly relative to the sandbox user's home directory; `~`
//!   and absolute paths are rejected at construction.
//! - **The apply layer** is responsible for `$VAR` expansion and
//!   canonicalization across the board.
//!
//! # Example user config
//!
//! ```toml
//! # User-origin patches — applied unconditionally outside hermetic builds.
//! # Only `ignore` from `[patch_policy]` filters these; `allow`/`deny` are
//! # bypassed.
//! patches = [
//!     { dest = ".gitconfig",                       source = "~/dotfiles/gitconfig" },
//!     { dest = ".config/alacritty/alacritty.toml", source = "~/dotfiles/alacritty.toml" },
//!     { dest = ".config/nvim/",                    source = "~/dotfiles/nvim/**/*" },
//!
//!     # Multi-pattern to one dest fans out into one entry per pattern:
//!     { dest = "Pictures/wallpapers/",             source = ["~/dotfiles/wallpapers/*.jpg",
//!                                                            "~/dotfiles/wallpapers/*.png"] },
//! ]
//!
//! # Policy for non-user patches (project and package origins).
//! # `ignore` here also applies to user-origin patches above.
//! [patch_policy]
//! allow  = ["~/.config/**", "~/.local/share/applications/**", "/etc/xdg/**"]
//! deny   = ["~/.ssh/**", "~/.aws/**", "**/id_rsa*", "**/*.pem"]
//! ignore = ["**/.DS_Store", "**/*.bak", "**/*.swp"]
//! ```

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use paths::{HostAbsPath, HostPath, SandboxRelPath};

/// Errors produced when constructing patch types.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    /// Returns [`Error::InvalidGlob`] if `pattern` fails to parse.
    pub fn try_new(pattern: impl Into<String>) -> Result<Self, Error> {
        let pattern = pattern.into();
        let glob = globset::Glob::new(&pattern)
            .map_err(|source| Error::InvalidGlob { pattern, source })?;
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
    #[must_use]
    pub fn walk_root(&self) -> Option<HostPath> {
        let pattern = self.pattern();
        let mut last_slash = None;
        for (i, c) in pattern.bytes().enumerate() {
            match c {
                b'/' => last_slash = Some(i),
                b'*' | b'?' | b'[' | b'{' => {
                    return last_slash.map(|i| HostPath::new(&pattern[..i]));
                }
                _ => {}
            }
        }
        Some(HostPath::new(pattern))
    }

    /// Walk the host filesystem under [`Self::walk_root`] and collect
    /// every file whose path matches this pattern.
    ///
    /// Per-entry failures (walk errors, non-UTF-8 paths) are accumulated
    /// into the returned `Vec<Error>` rather than aborting the walk —
    /// callers decide whether a partial result is acceptable.
    ///
    /// `~` and `$VAR` are **not** expanded; the walker passes the raw
    /// prefix to the OS. Expand before invoking, or accept that
    /// `~/...` patterns resolve to nothing.
    ///
    /// Patterns with no literal path prefix (e.g. `**/*.pem`, `*.lua`)
    /// would have to start their walk from `/` — virtually never what
    /// the caller wants. Such patterns produce an empty result with a
    /// single [`Error::NoWalkRoot`] entry instead of walking the entire
    /// root filesystem.
    #[must_use]
    pub fn resolve(&self, follow_links: bool) -> (Vec<HostPath>, Vec<Error>) {
        let Some(root) = self.walk_root() else {
            return (
                Vec::new(),
                vec![Error::NoWalkRoot {
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
                    Ok(p) if self.is_match(&p) => paths.push(HostPath::new(p)),
                    Ok(_) => {}
                    Err(p) => errors.push(Error::NonUtf8Path {
                        path_lossy: p.to_string_lossy().into_owned(),
                    }),
                },
                Err(source) => errors.push(Error::WalkFailure {
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
/// Wraps a [`SandboxRelPath`], so the realm tag is preserved through to
/// the apply layer. No `AsRef<std::path::Path>` is provided on purpose:
/// a destination path cannot be passed to host I/O without going through
/// a [`paths::Translator`] first.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PatchDest(SandboxRelPath);

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
        Ok(Self(
            SandboxRelPath::try_new(path).map_err(Error::AbsoluteDestPath)?,
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

/// A single patch: a source fileset on the host and the destination
/// inside the sandbox (relative to the sandbox user's home directory)
/// where its content should land.
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
            One(FileSet),
            Many(Vec<FileSet>),
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
                Source::One(fs) => out.push(Patch {
                    description,
                    source: fs,
                    dest,
                }),
                Source::Many(fss) => {
                    for fs in fss {
                        out.push(Patch {
                            description: description.clone(),
                            source: fs,
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

impl IntoIterator for Patches {
    type Item = Patch;
    type IntoIter = std::vec::IntoIter<Patch>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// =====================================================================
// PatchPolicy
// =====================================================================

/// Policy gating which patches are honored.
///
/// Patches are checked **per source file** after the patch's
/// [`FileSet`] is walked on the host filesystem. Each enumerated source
/// path runs through this policy; the patch's `dest` is *not* matched.
///
/// - **User-origin patches** (from a [`Loadout`]): only
///   [`ignore`](Self::ignore) applies. `allow` and `deny` are bypassed —
///   the user is the policy for their own declarations.
/// - **Project- and Package-origin patches**: all three fields apply.
///   A source file is honored iff its host path matches `allow`, does
///   not match `deny`, and does not match `ignore`. Files matching only
///   `ignore` are silently dropped; matching `deny` is an error;
///   matching neither `allow` nor `ignore` triggers a permission prompt
///   via [`PolicyHooks`](crate::composable::PolicyHooks).
///
/// Precedence: `ignore` first (silent), then `deny` (reject), then
/// `allow` (permit). Anything else prompts.
///
/// # `~` expansion
///
/// Policy patterns may start with `~`. The session resolver expands
/// them against `dirs::home_dir` (or a `Composer::with_home(...)`
/// override) at the start of `resolve_patches`, and again after any
/// [`PolicyHooks`](crate::composable::PolicyHooks) callback returns
/// an updated policy. Patterns retain their `~` form in the policy
/// returned from
/// [`Composer::resolve`](crate::composable::Composer::resolve), so
/// the policy round-trips losslessly across save / load.
///
/// When any `~`-prefixed pattern is in scope, home is resolved once
/// up-front. Both failure modes — no home available, or a non-UTF-8
/// home path — surface as
/// [`ResolveError::HomeUnresolved`](crate::composable::ResolveError::HomeUnresolved)
/// carrying a
/// [`HomeResolutionFailure`](crate::composable::HomeResolutionFailure)
/// to distinguish them. They are **not** silently dropped.
///
/// **Fast path:** a policy whose patterns contain no `~` does not
/// invoke the home lookup at all. This means a `~`-free policy
/// resolves cleanly even when `dirs::home_dir` returns `None`.
///
/// [`Loadout`]: crate::loadout::Loadout
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatchPolicy {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    allow: Vec<FileSet>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    deny: Vec<FileSet>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    ignore: Vec<FileSet>,
}

/// Accepts either a single pattern (bare string) or a list of patterns.
fn deserialize_one_or_many<'de, D>(d: D) -> Result<Vec<FileSet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        One(FileSet),
        Many(Vec<FileSet>),
    }
    Ok(match Repr::deserialize(d)? {
        Repr::One(f) => vec![f],
        Repr::Many(v) => v,
    })
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
    pub fn with_allow(self, allow: Vec<FileSet>) -> Self {
        Self { allow, ..self }
    }

    /// Replace the `deny` set.
    #[must_use]
    pub fn with_deny(self, deny: Vec<FileSet>) -> Self {
        Self { deny, ..self }
    }

    /// Replace the `ignore` set.
    #[must_use]
    pub fn with_ignore(self, ignore: Vec<FileSet>) -> Self {
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
        Ok(self.with_allow(try_collect_filesets(patterns)?))
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
        Ok(self.with_deny(try_collect_filesets(patterns)?))
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
        Ok(self.with_ignore(try_collect_filesets(patterns)?))
    }

    /// Paths non-user patches **may** target. Does not apply to
    /// user-origin patches.
    #[must_use]
    pub fn allow(&self) -> &[FileSet] {
        &self.allow
    }

    /// Paths non-user patches **must not** target. Does not apply to
    /// user-origin patches.
    #[must_use]
    pub fn deny(&self) -> &[FileSet] {
        &self.deny
    }

    /// Paths to silently drop without prompting. **Applies to every
    /// origin, user-origin included.**
    #[must_use]
    pub fn ignore(&self) -> &[FileSet] {
        &self.ignore
    }

    /// Categorize a single source-file path against this policy.
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
    /// Per-pattern provenance is preserved on the `FileSet` slices for a
    /// later inspection command; the decision itself does not name it.
    ///
    /// [`Source::UserLoadout`]: crate::composable::Source::UserLoadout
    /// [`Provenanced`]: crate::composable::Provenanced
    #[must_use]
    pub fn check<T: crate::composable::Provenanced>(
        &self,
        path: &Utf8Path,
        item: T,
    ) -> crate::composable::CheckOutcome<T> {
        use crate::composable::{CheckOutcome, Decision, Source};
        if filesets_match(&self.ignore, path) {
            return CheckOutcome::Decided(Decision::Ignored);
        }
        if matches!(item.source(), Source::UserLoadout { .. }) {
            return CheckOutcome::Decided(Decision::Allowed(item));
        }
        if filesets_match(&self.deny, path) {
            CheckOutcome::Decided(Decision::Denied(item))
        } else if filesets_match(&self.allow, path) {
            CheckOutcome::Decided(Decision::Allowed(item))
        } else {
            CheckOutcome::NeedsApproval(item)
        }
    }
}

/// `true` iff any `FileSet` in `sets` matches `path`.
fn filesets_match(sets: &[FileSet], path: &Utf8Path) -> bool {
    sets.iter().any(|fs| fs.is_match(path))
}

fn try_collect_filesets<I, S>(patterns: I) -> Result<Vec<FileSet>, Error>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    patterns.into_iter().map(FileSet::try_new).collect()
}

/// A single patch's resolved endpoints: where the file lives on the
/// host, and where it lands inside the sandbox (relative to the
/// sandbox user's home directory).
///
/// The field is `host_path` (not `source`) so it doesn't collide with
/// [`Provenanced::source`](crate::composable::Provenanced::source) when
/// accessed via `SessionPatch::patch().host_path()`.
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

    fn patterns(sets: &[FileSet]) -> Vec<&str> {
        sets.iter().map(FileSet::pattern).collect()
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
            let expected = expected.map(HostPath::new);
            assert_eq!(fs.walk_root(), expected, "pattern: {pattern}");
        }
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
        assert_eq!(p.source().pattern(), "./foo.conf");
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
        let sources: Vec<_> = ps.iter().map(|p| p.source().pattern().to_owned()).collect();
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

    // ---- PatchPolicy ----

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
            .try_with_allow(["~/.config/**"])
            .unwrap()
            .try_with_deny(["~/.ssh/**", "**/*.pem"])
            .unwrap()
            .try_with_ignore(["**/.DS_Store"])
            .unwrap();
        assert_eq!(patterns(p.allow()), ["~/.config/**"]);
        assert_eq!(patterns(p.deny()), ["~/.ssh/**", "**/*.pem"]);
        assert_eq!(patterns(p.ignore()), ["**/.DS_Store"]);
    }

    #[test]
    fn patch_policy_try_with_allow_propagates_invalid_glob() {
        let err = PatchPolicy::empty().try_with_allow(["[bad"]).unwrap_err();
        assert!(matches!(err, Error::InvalidGlob { .. }), "got: {err:?}");
    }

    #[test]
    fn patch_policy_skips_empty_fields_on_serialize() {
        let p = PatchPolicy::empty().try_with_allow(["A"]).unwrap();
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("allow"), "expected allow, got: {s}");
        assert!(!s.contains("deny"), "expected no deny, got: {s}");
        assert!(!s.contains("ignore"), "expected no ignore, got: {s}");
    }

    // ---- Patches builders ----

    #[test]
    fn patches_builder_surfaces_compose() {
        let make =
            |s: &str| Patch::new(FileSet::try_new(s).unwrap(), PatchDest::try_new(s).unwrap());

        let collected: Patches = ["a", "b"].into_iter().map(make).collect();
        let mut built = Patches::empty().with_patch(make("a"));
        built.push(make("b"));
        assert_eq!(collected, built);
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn patches_extend_appends_other_collection() {
        let make =
            |s: &str| Patch::new(FileSet::try_new(s).unwrap(), PatchDest::try_new(s).unwrap());
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
