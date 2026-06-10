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

use camino::{Utf8Component, Utf8PathBuf};
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
                    return last_slash.map(|s| HostPath::new(literal[..s].to_owned()));
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
                    return last_slash.map(|s| HostPath::new(literal[..s].to_owned()));
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
        Some(HostPath::new(literal))
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
    /// Returns [`Error::EmptyDest`] for empty paths, or
    /// [`Error::DestTraversal`] for paths containing `..` components.
    pub fn try_new(path: impl Into<Utf8PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        if path.as_str().is_empty() {
            return Err(Error::EmptyDest);
        }
        // Walk components: drop CurDir, fail on ParentDir, keep the
        // rest. RootDir (an absolute path) is allowed through here so
        // SandboxRelPath::try_new can produce its own AbsoluteDestPath
        // error — that gives a more specific message than failing here.
        let mut normalized = Utf8PathBuf::new();
        for component in path.components() {
            match component {
                Utf8Component::CurDir => {}
                Utf8Component::ParentDir => return Err(Error::DestTraversal(path)),
                other => normalized.push(other.as_str()),
            }
        }
        Ok(Self(
            SandboxRelPath::try_new(normalized).map_err(Error::AbsoluteDestPath)?,
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
/// — it may contain `~/` or `$VAR` / `${VAR}` references. Resolution
/// against the session's resolved variables happens later (see
/// [`crate::expansion::expand_source`]); attempting to parse it as a
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
/// [`Loadout`]: crate::loadout::Loadout
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
/// # `~/` and `$VAR` expansion
///
/// Policy patterns are stored as raw strings, so they may contain
/// `~/` prefixes or `$VAR` / `${VAR}` references. Expansion happens
/// at session-construction time, against the session's resolved
/// variables (see
/// [`crate::expansion::expand_source`]). Patterns retain their raw
/// form in the policy returned from
/// [`Composer::resolve`](crate::composable::Composer::resolve), so
/// the policy round-trips losslessly across save / load.
///
/// [`Loadout`]: crate::loadout::Loadout
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
    /// not validated until expansion happens at resolution time.
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

    /// Raw patterns non-user patches **may** target. Does not apply to
    /// user-origin patches.
    #[must_use]
    pub fn allow(&self) -> &[String] {
        &self.allow
    }

    /// Raw patterns non-user patches **must not** target. Does not
    /// apply to user-origin patches.
    #[must_use]
    pub fn deny(&self) -> &[String] {
        &self.deny
    }

    /// Raw patterns silently dropped without prompting. **Applies to
    /// every origin, user-origin included.**
    #[must_use]
    pub fn ignore(&self) -> &[String] {
        &self.ignore
    }

    /// Expand the raw patterns against `resolved_vars` and produce an
    /// [`ExpandedPatchPolicy`] suitable for matching.
    ///
    /// Every pattern is run through
    /// [`crate::expansion::expand_source`]; the first failure stops
    /// the expansion and is returned.
    ///
    /// # Errors
    ///
    /// Returns the first [`crate::expansion::ExpandError`] produced
    /// by any pattern.
    ///
    /// [`ExpandedPatchPolicy`]: crate::composable::ExpandedPatchPolicy
    pub fn expand_with(
        &self,
        resolved_vars: &[crate::composable::SessionVar],
        home_fallback: Option<&str>,
    ) -> Result<crate::composable::ExpandedPatchPolicy, crate::expansion::ExpandError> {
        let expand_one = |raws: &[String]| -> Result<Vec<FileSet>, crate::expansion::ExpandError> {
            raws.iter()
                .map(|r| crate::expansion::expand_source(r, resolved_vars, home_fallback))
                .collect()
        };
        let allow = expand_one(&self.allow)?;
        let deny = expand_one(&self.deny)?;
        let ignore = expand_one(&self.ignore)?;
        Ok(crate::composable::ExpandedPatchPolicy::from_expanded(
            allow, deny, ignore,
        ))
    }
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

    fn patterns(sets: &[String]) -> Vec<&str> {
        sets.iter().map(String::as_str).collect()
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

    // ---- Patches builders ----

    #[test]
    fn patches_builder_surfaces_compose() {
        let make = |s: &str| Patch::new(s, PatchDest::try_new(s).unwrap());

        let collected: Patches = ["a", "b"].into_iter().map(make).collect();
        let mut built = Patches::empty().with_patch(make("a"));
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

    // ---- PatchPolicy::expand_with ----

    /// Build a `SessionVar` with the given name + value. Uses a
    /// user-origin source because resolution doesn't consult it.
    fn sv(name: &str, value: &str) -> crate::composable::SessionVar {
        let resolved = crate::vars::ResolvedVar::resolve_with(
            name.into(),
            crate::vars::VarValue::specified(value),
            |_| Err(std::env::VarError::NotPresent),
        )
        .unwrap();
        crate::composable::SessionVar::new(
            resolved,
            crate::composable::Source::UserLoadout {
                name: "test".into(),
            },
        )
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
        let expanded = policy.expand_with(&vars, None).unwrap();
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
        let vars = [];
        let err = policy.expand_with(&vars, None).unwrap_err();
        assert!(
            matches!(
                err,
                crate::expansion::ExpandError::UndefinedVar { ref name }
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
        let vars = [];
        let expanded = policy.expand_with(&vars, None).unwrap();
        // Patterns pass through globset intact.
        assert_eq!(expanded.allow().len(), 1);
        assert_eq!(expanded.deny().len(), 1);
        assert_eq!(expanded.ignore().len(), 1);
    }
}
